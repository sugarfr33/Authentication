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

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T13 through the real pipeline: login, logout, logout-all and /me with cookies, CSRF, lockout and audit. The login
/// limits are raised for this class so the tests do not throttle each other.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class SessionApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Login = "/api/v1/auth/login";
    private const string Logout = "/api/v1/auth/logout";
    private const string LogoutAll = "/api/v1/auth/logout-all";
    private const string Me = "/api/v1/auth/me";
    private const string Password = "violet-canyon-7319";

    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
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
    public async Task Login_sets_HttpOnly_cookies_only_and_returns_the_profile_without_tokens()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        string xsrfBefore = browser.Xsrf!;

        HttpResponseMessage response = await LoginAsync(browser, email, Password);
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        IReadOnlyList<SetCookie> cookies = SetCookie.From(response);
        SetCookie access = Assert.Single(cookies, c => c.Name == AuthCookieNames.Access);
        SetCookie refresh = Assert.Single(cookies, c => c.Name == AuthCookieNames.Refresh);
        Assert.All([access, refresh], c => Assert.True(c.HasFlag("httponly") && c.HasFlag("secure")));
        Assert.Equal("/", access["path"]);
        Assert.Equal("/api/v1/auth/refresh", refresh["path"]);
        Assert.DoesNotContain(access.Value, body, StringComparison.Ordinal);
        Assert.DoesNotContain(refresh.Value, body, StringComparison.Ordinal);
        Assert.DoesNotContain("token", body, StringComparison.OrdinalIgnoreCase);
        Assert.False(response.HasHeader("Authorization"));

        JsonNode profile = JsonNode.Parse(body)!;
        Assert.Equal(email, profile["email"]!.GetValue<string>());
        Assert.True(profile["emailVerified"]!.GetValue<bool>());
        Assert.NotEqual(xsrfBefore, browser.Xsrf);
    }

    [Fact]
    public async Task Me_returns_the_profile_without_secrets_and_401_when_signed_out()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        HttpResponseMessage anonymous = await browser.GetAsync(Me);
        await LoginAsync(browser, email, Password);

        HttpResponseMessage me = await browser.GetAsync(Me);
        string body = await me.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal("application/problem+json", anonymous.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(email, JsonNode.Parse(body)!["email"]!.GetValue<string>());
        foreach (string secret in new[] { "password", "hash", "stamp", "rowVersion", "mfaSecret", "lockout", "failed" })
        {
            Assert.DoesNotContain(secret, body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Every_failed_login_reason_gets_the_identical_answer_and_no_cookies()
    {
        string good = await SeedUserAsync();
        string unverified = await SeedUserAsync(verified: false);
        string inactive = await SeedUserAsync(active: false);
        string locked = await SeedUserAsync(lockedUntil: DateTime.UtcNow.AddHours(1));
        string noPassword = await SeedUserAsync(passwordHash: string.Empty);
        using Browser browser = await ReadyBrowserAsync();

        (string Email, string Password)[] attempts =
        [
            (good, "wrong-password-0000"),
            ("nobody-" + Guid.NewGuid().ToString("N")[..8] + "@example.test", Password),
            (unverified, Password),
            (inactive, Password),
            (locked, Password),
            (noPassword, Password),
            (good, string.Empty),
            (good, new string('x', 5000)),
            (new string('a', 300) + "@example.test", Password),
        ];

        List<string> answers = [];
        foreach ((string email, string password) in attempts)
        {
            HttpResponseMessage response = await LoginAsync(browser, email, password);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.DoesNotContain(SetCookie.From(response), c => c.Name is AuthCookieNames.Access or AuthCookieNames.Refresh);
            answers.Add(response.Content.Headers.ContentType + " " + WithoutTraceId(await response.Content.ReadAsStringAsync()));
        }

        Assert.Single(answers.Distinct(StringComparer.Ordinal));
        Assert.Contains("Invalid email or password.", answers[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Five_wrong_passwords_lock_the_account_and_the_right_one_then_fails_the_same_way()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();

        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(browser, email, "wrong-password-" + i)).StatusCode);
        }

        HttpResponseMessage right = await LoginAsync(browser, email, Password);

        Assert.Equal(HttpStatusCode.Unauthorized, right.StatusCode);
        User user = await LoadUserAsync(email);
        Assert.True(user.LockoutEndUtc > DateTime.UtcNow);
        List<AuditLog> audit = await AuditAsync(user.Id);
        Assert.Equal(6, audit.Count(a => a.EventType == nameof(AuditEventType.LoginFailed)));
        Assert.Single(audit, a => a.EventType == nameof(AuditEventType.Lockout));
        Assert.Contains(audit, a => a.Detail == """{"reason":"locked"}""");
        Assert.DoesNotContain(audit, a => a.EventType == nameof(AuditEventType.LoginSucceeded));
    }

    [Fact]
    public async Task Logout_clears_both_cookies_revokes_the_family_and_reissues_XSRF()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        await LoginAsync(browser, email, Password);
        string xsrfSignedIn = browser.Xsrf!;
        Guid userId = (await LoadUserAsync(email)).Id;

        HttpResponseMessage logout = await browser.SendAsync(HttpMethod.Post, Logout);

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        IReadOnlyList<SetCookie> cookies = SetCookie.From(logout);
        Assert.True(Assert.Single(cookies, c => c.Name == AuthCookieNames.Access).IsExpired);
        Assert.True(Assert.Single(cookies, c => c.Name == AuthCookieNames.Refresh).IsExpired);
        Assert.False(browser.HasCookie(AuthCookieNames.Access));
        Assert.NotEqual(xsrfSignedIn, browser.Xsrf);
        RefreshToken family = Assert.Single(await RefreshTokensAsync(userId));
        Assert.Equal(RefreshTokenRevokedReason.Logout, family.RevokedReason);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync(Me)).StatusCode);
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.Logout) && a.IpAddress == ApiFixture.TestRemoteIp);
    }

    [Fact]
    public async Task Logout_all_revokes_every_session_of_the_user()
    {
        string email = await SeedUserAsync();
        using Browser laptop = await ReadyBrowserAsync();
        using Browser phone = await ReadyBrowserAsync();
        await LoginAsync(laptop, email, Password);
        await LoginAsync(phone, email, Password);
        Guid userId = (await LoadUserAsync(email)).Id;
        Assert.Equal(2, (await RefreshTokensAsync(userId)).Count(t => t.RevokedUtc is null));

        HttpResponseMessage response = await phone.SendAsync(HttpMethod.Post, LogoutAll);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        List<RefreshToken> families = await RefreshTokensAsync(userId);
        Assert.Equal(2, families.Count);
        Assert.All(families, t => Assert.Equal(RefreshTokenRevokedReason.LogoutAll, t.RevokedReason));
        Assert.False(phone.HasCookie(AuthCookieNames.Access));
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.LogoutAll) && a.Detail == """{"revoked":2}""");
    }

    [Fact]
    public async Task Logout_all_needs_a_signed_in_user()
    {
        using Browser browser = await ReadyBrowserAsync();

        HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, LogoutAll);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task State_changing_calls_need_the_antiforgery_token()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();

        HttpResponseMessage loginWithoutXsrf = await browser.SendAsync(HttpMethod.Post, Login, sendXsrf: false, configure: r => r.Content = Json(email, Password));
        await LoginAsync(browser, email, Password);
        HttpResponseMessage logoutAllWithoutXsrf = await browser.SendAsync(HttpMethod.Post, LogoutAll, sendXsrf: false);
        HttpResponseMessage logoutWithoutXsrf = await browser.SendAsync(HttpMethod.Post, Logout, sendXsrf: false);
        HttpResponseMessage logoutFromOtherOrigin = await browser.SendAsync(HttpMethod.Post, Logout, originOverride: "https://evil.example.test");

        Assert.Equal(HttpStatusCode.BadRequest, loginWithoutXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, logoutAllWithoutXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, logoutWithoutXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, logoutFromOtherOrigin.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task Successful_login_is_audited_and_the_refresh_family_records_ip_and_user_agent()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();

        await browser.SendAsync(HttpMethod.Post, Login, configure: r =>
        {
            r.Content = Json(email, Password);
            r.Headers.TryAddWithoutValidation("User-Agent", "SessionTests/1.0");
        });

        User user = await LoadUserAsync(email);
        RefreshToken family = Assert.Single(await RefreshTokensAsync(user.Id));
        Assert.Equal((ApiFixture.TestRemoteIp, "SessionTests/1.0"), (family.IpAddress, family.UserAgent));
        Assert.NotNull(user.LastLoginUtc);
        Assert.Contains(await AuditAsync(user.Id), a => a.EventType == nameof(AuditEventType.LoginSucceeded) && a.UserAgent == "SessionTests/1.0");
        Assert.DoesNotContain(api.Logs.Texts, t => t.Contains(Password, StringComparison.Ordinal));
    }

    private static StringContent Json(string email, string password) =>
        new(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = password }), Encoding.UTF8, "application/json");

    private static Task<HttpResponseMessage> LoginAsync(Browser browser, string email, string password) =>
        browser.SendAsync(HttpMethod.Post, Login, configure: r => r.Content = Json(email, password));

    private static string WithoutTraceId(string json)
    {
        JsonObject problem = JsonNode.Parse(json)!.AsObject();
        problem.Remove("traceId");
        return problem.ToJsonString();
    }

    private async Task<Browser> ReadyBrowserAsync()
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return browser;
    }

    private async Task<string> SeedUserAsync(bool verified = true, bool active = true, DateTime? lockedUntil = null, string? passwordHash = null)
    {
        string email = "session-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string hash = passwordHash ?? await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        context.User.Add(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = verified,
            PasswordHash = hash,
            DisplayName = "Session Tester",
            IsActive = active,
            LockoutEndUtc = lockedUntil,
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

    private Task<List<RefreshToken>> RefreshTokensAsync(Guid userId) =>
        QueryAsync(context => context.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync());

    private Task<List<AuditLog>> AuditAsync(Guid userId) =>
        QueryAsync(context => context.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());
}
