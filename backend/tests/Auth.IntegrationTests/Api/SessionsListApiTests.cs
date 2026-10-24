using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Auth.IntegrationTests.Api;

/// <summary>T15 through the real pipeline: list and revoke sessions, and /refresh for revoked sessions.</summary>
[Collection(ApiTestGroup.Name)]
public sealed class SessionsListApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Sessions = "/api/v1/auth/sessions";
    private const string Refresh = "/api/v1/auth/refresh";
    private const string Login = "/api/v1/auth/login";
    private const string Logout = "/api/v1/auth/logout";
    private const string Me = "/api/v1/auth/me";
    private const string Password = "violet-canyon-7319";

    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Refresh:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Sessions:PerIp:PermitLimit"] = "1000",
        };
        app = api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        });
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task Users_see_only_their_own_sessions_with_the_current_one_flagged_and_no_secrets()
    {
        string alice = await SeedUserAsync();
        string bob = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(alice);
        using Browser phone = await SignedInAsync(alice);
        using Browser bobs = await SignedInAsync(bob);

        HttpResponseMessage response = await laptop.GetAsync(Sessions);
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonArray list = JsonNode.Parse(body)!.AsArray();
        Assert.Equal(
            new[] { SessionOf(laptop), SessionOf(phone) }.Order(),
            list.Select(s => Guid.Parse(s!["familyId"]!.GetValue<string>())).Order());
        Assert.Equal(SessionOf(laptop), Guid.Parse(Assert.Single(list, s => s!["isCurrent"]!.GetValue<bool>())!["familyId"]!.GetValue<string>()));
        Assert.All(list, s => Assert.Equal(
            ["createdUtc", "familyId", "ip", "isCurrent", "lastUsedUtc", "userAgent"],
            s!.AsObject().Select(p => p.Key).Order(StringComparer.Ordinal)));
        foreach (Browser browser in new[] { laptop, phone, bobs })
        {
            Assert.DoesNotContain(browser.CookieValue(AuthCookieNames.Refresh), body, StringComparison.Ordinal);
            Assert.DoesNotContain(browser.CookieValue(AuthCookieNames.Access), body, StringComparison.Ordinal);
        }

        Assert.DoesNotContain(SessionOf(bobs).ToString(), body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("stamp", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Another_users_session_unknown_and_malformed_ids_get_the_identical_404()
    {
        string alice = await SeedUserAsync();
        string bob = await SeedUserAsync();
        using Browser attacker = await SignedInAsync(alice);
        using Browser victim = await SignedInAsync(bob);
        Guid victimSession = SessionOf(victim);

        List<string> answers = [];
        foreach (string id in new[] { victimSession.ToString(), Guid.NewGuid().ToString(), "not-a-guid" })
        {
            HttpResponseMessage response = await attacker.SendAsync(HttpMethod.Delete, Sessions + "/" + id);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            answers.Add(response.Content.Headers.ContentType + " " + WithoutTraceId(await response.Content.ReadAsStringAsync()));
        }

        Assert.Single(answers.Distinct(StringComparer.Ordinal));
        Assert.Equal(HttpStatusCode.NoContent, (await victim.SendAsync(HttpMethod.Post, Refresh)).StatusCode);
    }

    [Fact]
    public async Task A_revoked_session_cannot_refresh_and_revoking_again_is_harmless()
    {
        string alice = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(alice);
        using Browser phone = await SignedInAsync(alice);
        Guid phoneSession = SessionOf(phone);

        HttpResponseMessage revoke = await laptop.SendAsync(HttpMethod.Delete, Sessions + "/" + phoneSession);
        HttpResponseMessage again = await laptop.SendAsync(HttpMethod.Delete, Sessions + "/" + phoneSession);
        HttpResponseMessage phoneRefresh = await phone.SendAsync(HttpMethod.Post, Refresh);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, phoneRefresh.StatusCode);
        Assert.False(phone.HasCookie(AuthCookieNames.Refresh));
        Assert.Equal(HttpStatusCode.OK, (await laptop.GetAsync(Me)).StatusCode);
        Assert.DoesNotContain(phoneSession.ToString(), await (await laptop.GetAsync(Sessions)).Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        Guid aliceId = (await LoadUserAsync(alice)).Id;
        Assert.Single(await AuditAsync(aliceId), a => a.EventType == nameof(AuditEventType.SessionRevoked));
    }

    [Fact]
    public async Task Revoking_the_current_session_signs_this_browser_out()
    {
        string alice = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(alice);

        HttpResponseMessage revoke = await laptop.SendAsync(HttpMethod.Delete, Sessions + "/" + SessionOf(laptop));

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.True(Assert.Single(SetCookie.From(revoke), c => c.Name == AuthCookieNames.Access).IsExpired);
        Assert.True(Assert.Single(SetCookie.From(revoke), c => c.Name == AuthCookieNames.Refresh).IsExpired);
        Assert.Equal(HttpStatusCode.Unauthorized, (await laptop.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task Revoking_needs_the_antiforgery_token_and_listing_needs_a_session()
    {
        string alice = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(alice);
        using Browser anonymous = await ReadyBrowserAsync();

        HttpResponseMessage withoutXsrf = await laptop.SendAsync(HttpMethod.Delete, Sessions + "/" + SessionOf(laptop), sendXsrf: false);
        HttpResponseMessage list = await anonymous.GetAsync(Sessions);

        Assert.Equal(HttpStatusCode.BadRequest, withoutXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await laptop.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task Ended_and_expired_sessions_are_not_listed()
    {
        string alice = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(alice);
        using Browser old = await SignedInAsync(alice);
        Guid oldSession = SessionOf(old);
        await old.SendAsync(HttpMethod.Post, Logout);
        Guid userId = (await LoadUserAsync(alice)).Id;
        Guid expiredFamily = Guid.NewGuid();
        await QueryAsync(async context =>
        {
            context.RefreshToken.Add(new RefreshToken
            {
                UserId = userId,
                FamilyId = expiredFamily,
                TokenHash = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
                CreatedUtc = DateTime.UtcNow.AddDays(-20),
                ExpiresUtc = DateTime.UtcNow.AddMinutes(-1),
                IpAddress = "203.0.113.50",
                UserAgent = "old",
            });
            return await context.SaveChangesAsync();
        });

        string body = await (await laptop.GetAsync(Sessions)).Content.ReadAsStringAsync();

        JsonArray list = JsonNode.Parse(body)!.AsArray();
        Assert.Equal(SessionOf(laptop), Guid.Parse(Assert.Single(list)!["familyId"]!.GetValue<string>()));
        Assert.DoesNotContain(oldSession.ToString(), body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(expiredFamily.ToString(), body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Refresh_keeps_the_session_start_and_updates_its_last_use()
    {
        string alice = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(alice);
        JsonNode before = JsonNode.Parse(await (await laptop.GetAsync(Sessions)).Content.ReadAsStringAsync())!.AsArray().Single()!;
        string oldRefresh = laptop.CookieValue(AuthCookieNames.Refresh);
        await Task.Delay(20);

        HttpResponseMessage refresh = await laptop.SendAsync(HttpMethod.Post, Refresh);
        JsonNode after = JsonNode.Parse(await (await laptop.GetAsync(Sessions)).Content.ReadAsStringAsync())!.AsArray().Single()!;

        Assert.Equal(HttpStatusCode.NoContent, refresh.StatusCode);
        Assert.NotEqual(oldRefresh, laptop.CookieValue(AuthCookieNames.Refresh));
        Assert.Equal(before["familyId"]!.GetValue<string>(), after["familyId"]!.GetValue<string>());
        Assert.Equal(before["createdUtc"]!.GetValue<DateTime>(), after["createdUtc"]!.GetValue<DateTime>());
        Assert.True(after["lastUsedUtc"]!.GetValue<DateTime>() > before["lastUsedUtc"]!.GetValue<DateTime>());
        Assert.True(after["isCurrent"]!.GetValue<bool>());
        Assert.Equal(HttpStatusCode.OK, (await laptop.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task User_agent_and_ip_are_cleaned_and_capped_for_display()
    {
        string alice = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        string userAgent = "Evil<script>alert(1)</script>" + '\u0007' + '​' + new string('x', 600);
        await browser.SendAsync(HttpMethod.Post, Login, configure: r =>
        {
            r.Content = LoginJson(alice);
            r.Headers.TryAddWithoutValidation("User-Agent", userAgent);
        });

        string body = await (await browser.GetAsync(Sessions)).Content.ReadAsStringAsync();
        string shown = JsonNode.Parse(body)!.AsArray().Single()!["userAgent"]!.GetValue<string>();

        Assert.True(shown.Length <= 256);
        Assert.DoesNotContain('\u0007', shown);
        Assert.DoesNotContain('​', shown);
        Assert.DoesNotContain('<', shown);
        Assert.DoesNotContain('>', shown);
        Assert.StartsWith("Evilscriptalert(1)/script", shown, StringComparison.Ordinal);
    }

    private static Guid SessionOf(Browser browser) =>
        Guid.Parse(new JsonWebToken(browser.CookieValue(AuthCookieNames.Access)).GetClaim(AuthClaimTypes.SessionId).Value);

    private static string WithoutTraceId(string json)
    {
        JsonObject problem = JsonNode.Parse(json)!.AsObject();
        problem.Remove("traceId");
        return problem.ToJsonString();
    }

    private static StringContent LoginJson(string email) =>
        new(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }), Encoding.UTF8, "application/json");

    private async Task<Browser> SignedInAsync(string email)
    {
        Browser browser = await ReadyBrowserAsync();
        HttpResponseMessage login = await browser.SendAsync(HttpMethod.Post, Login, configure: r => r.Content = LoginJson(email));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return browser;
    }

    private async Task<Browser> ReadyBrowserAsync()
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return browser;
    }

    private async Task<string> SeedUserAsync()
    {
        string email = "sessions-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        context.User.Add(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = true,
            PasswordHash = hash,
            DisplayName = "Sessions Tester",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        });
        await context.SaveChangesAsync();
        return email;
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private Task<User> LoadUserAsync(string email) =>
        QueryAsync(context => context.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)));

    private Task<List<AuditLog>> AuditAsync(Guid userId) =>
        QueryAsync(context => context.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());
}
