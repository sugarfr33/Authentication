using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.ClientApplications;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Api;

/// <summary>T20 single logout, RP-initiated logout and the two cookie modes (docs/single-logout-and-shared-domain.md).</summary>
[Collection(ApiTestGroup.Name)]
public sealed class SingleLogoutApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Password = "violet-canyon-7319";
    private const string NewPassword = "amber-harbor-5520";
    private const string OAuthLogout = "/api/v1/oauth/logout";

    private readonly ShiftableClock clock = new();
    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        app = WithSettings([]);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task Logout_ends_every_application_session_of_the_user()
    {
        Spa first = await RegisterSpaAsync();
        Spa second = await RegisterSpaAsync();
        (Guid userId, Browser browser) = await SignedInAsync();
        OAuthTokenResponse a = await AppSessionAsync(browser, first);
        OAuthTokenResponse b = await AppSessionAsync(browser, second);

        HttpResponseMessage logout = await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/logout");

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Equal("invalid_grant", await RefreshErrorAsync(first, a.RefreshToken));
        Assert.Equal("invalid_grant", await RefreshErrorAsync(second, b.RefreshToken));
        AuditLog single = Assert.Single(await AuditAsync(userId), r => r.EventType == nameof(AuditEventType.SingleLogout));
        Assert.Equal("""{"cause":"logout","revoked":2}""", single.Detail);
    }

    [Fact]
    public async Task Logout_all_and_a_password_change_end_the_application_sessions()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        OAuthTokenResponse beforeLogoutAll = await AppSessionAsync(browser, spa);
        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/logout-all")).StatusCode);

        (_, Browser again) = await SignedInAsync();
        OAuthTokenResponse beforePasswordChange = await AppSessionAsync(again, spa);
        HttpResponseMessage change = await again.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password", configure: r =>
            r.Content = JsonContent.Create(new ChangePasswordRequest(Password, NewPassword)));

        Assert.True(change.IsSuccessStatusCode, change.StatusCode.ToString());
        Assert.Equal("invalid_grant", await RefreshErrorAsync(spa, beforeLogoutAll.RefreshToken));
        Assert.Equal("invalid_grant", await RefreshErrorAsync(spa, beforePasswordChange.RefreshToken));
    }

    [Fact]
    public async Task Revoking_a_browser_session_ends_the_application_sessions_but_revoking_an_application_session_ends_only_it()
    {
        Spa first = await RegisterSpaAsync();
        Spa second = await RegisterSpaAsync();
        (Guid userId, Browser browser) = await SignedInAsync();
        OAuthTokenResponse a = await AppSessionAsync(browser, first);
        OAuthTokenResponse b = await AppSessionAsync(browser, second);
        Guid appFamily = await FamilyOfAsync(userId, first);

        HttpResponseMessage revokeApp = await browser.SendAsync(HttpMethod.Delete, "/api/v1/auth/sessions/" + appFamily);

        Assert.Equal(HttpStatusCode.NoContent, revokeApp.StatusCode);
        Assert.Equal("invalid_grant", await RefreshErrorAsync(first, a.RefreshToken));
        OAuthTokenResponse bNext = await RefreshAsync(second, b.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);

        // Another browser session of the same user is revoked from this one: the application sessions end with it.
        (_, Browser other) = await SignInAgainAsync(userId);
        Guid otherFamily = (await QueryAsync(c => c.RefreshToken.AsNoTracking()
            .Where(t => t.UserId == userId && t.ClientApplicationId == null && t.RevokedUtc == null).OrderByDescending(t => t.CreatedUtc).FirstAsync())).FamilyId;
        HttpResponseMessage revokeBrowser = await browser.SendAsync(HttpMethod.Delete, "/api/v1/auth/sessions/" + otherFamily);

        Assert.Equal(HttpStatusCode.NoContent, revokeBrowser.StatusCode);
        Assert.Equal("invalid_grant", await RefreshErrorAsync(second, bNext.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task A_stolen_browser_refresh_token_replayed_ends_the_application_sessions()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        OAuthTokenResponse tokens = await AppSessionAsync(browser, spa);
        string stolen = browser.CookieValue(AuthCookieNames.Refresh);
        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh")).StatusCode);
        clock.Shift(TimeSpan.FromSeconds(11));

        using Browser thief = new(app);
        await thief.GetAsync(TestEndpoints.Prefix + "/ping");
        thief.Plant(AuthCookieNames.Refresh, stolen, "/api/v1/auth");
        HttpResponseMessage replay = await thief.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh");

        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal("invalid_grant", await RefreshErrorAsync(spa, tokens.RefreshToken));
    }

    [Fact]
    public async Task Deactivating_one_application_leaves_the_browser_and_the_other_applications_signed_in()
    {
        Spa first = await RegisterSpaAsync();
        Spa second = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        await AppSessionAsync(browser, first);
        OAuthTokenResponse b = await AppSessionAsync(browser, second);

        await using (AsyncServiceScope scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().DeactivateAsync(first.Id, AuditContext.None, CancellationToken.None);
        }

        await RefreshAsync(second, b.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    /// <summary>RP-initiated logout never redirects to anything but an exact registered post-logout URI.</summary>
    [Theory]
    [InlineData("https://evil.example.test/bye")]
    [InlineData("{0}/extra")]
    [InlineData("{0}x")]
    [InlineData("UPPER")]
    [InlineData("USERINFO")]
    [InlineData("{0}#fragment")]
    [InlineData("{0}?next=1")]
    [InlineData("")]
    public async Task An_unregistered_or_altered_post_logout_uri_is_never_a_target(string variant)
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        string host = new Uri(spa.PostLogoutUri).Host;
        string uri = variant switch
        {
            "UPPER" => spa.PostLogoutUri.Replace(host, host.ToUpperInvariant(), StringComparison.Ordinal),
            "USERINFO" => spa.PostLogoutUri.Replace("https://", "https://user@", StringComparison.Ordinal),
            _ => string.Format(System.Globalization.CultureInfo.InvariantCulture, variant, spa.PostLogoutUri),
        };

        HttpResponseMessage prompt = await browser.GetAsync(LogoutUrl(spa.ClientId, uri, "st-1"));
        HttpResponseMessage confirmed = await PostLogoutAsync(browser, new OAuthLogoutRequest(spa.ClientId, uri, "st-1"));

        foreach (HttpResponseMessage response in new[] { prompt, confirmed })
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.Null((await response.Content.ReadFromJsonAsync<OAuthLogoutResponse>())!.RedirectTo);
        }
    }

    [Fact]
    public async Task A_registered_post_logout_uri_is_returned_with_the_state_and_the_application_sessions_end()
    {
        Spa spa = await RegisterSpaAsync();
        Spa other = await RegisterSpaAsync();
        (Guid userId, Browser browser) = await SignedInAsync();
        OAuthTokenResponse mine = await AppSessionAsync(browser, spa);
        OAuthTokenResponse theirs = await AppSessionAsync(browser, other);

        HttpResponseMessage prompt = await browser.GetAsync(LogoutUrl(spa.ClientId, spa.PostLogoutUri, "s 1"));
        HttpResponseMessage confirmed = await PostLogoutAsync(browser, new OAuthLogoutRequest(spa.ClientId.ToUpperInvariant(), spa.PostLogoutUri, "s 1"));
        OAuthLogoutResponse answer = (await confirmed.Content.ReadFromJsonAsync<OAuthLogoutResponse>())!;

        Assert.Equal(HttpStatusCode.OK, prompt.StatusCode);
        Assert.Equal("no-store", prompt.Headers.CacheControl!.ToString());
        Assert.Contains("no-referrer", prompt.Headers.GetValues("Referrer-Policy"));
        Assert.Null(prompt.Headers.Location);
        Assert.Equal((spa.ClientId, spa.PostLogoutUri + "?state=s%201"), (answer.ClientId, answer.RedirectTo));
        Assert.Equal("invalid_grant", await RefreshErrorAsync(spa, mine.RefreshToken));
        await RefreshAsync(other, theirs.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);
        Assert.Contains(await AuditAsync(userId), r => r.EventType == nameof(AuditEventType.SingleLogout)
            && r.Detail!.Contains("application_logout", StringComparison.Ordinal) && r.Detail.Contains(spa.Id.ToString("D"), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unknown_clients_and_duplicate_parameters_get_an_error_on_our_domain()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();

        HttpResponseMessage unknown = await browser.GetAsync(LogoutUrl("no-such-client", spa.PostLogoutUri, "s"));
        HttpResponseMessage duplicate = await browser.GetAsync(LogoutUrl(spa.ClientId, spa.PostLogoutUri, "s") + "&post_logout_redirect_uri=" + Uri.EscapeDataString("https://evil.example.test"));
        HttpResponseMessage unknownPost = await PostLogoutAsync(browser, new OAuthLogoutRequest("no-such-client", spa.PostLogoutUri, null));

        Assert.Equal(("invalid_client", "invalid_request", "invalid_client"), (await ErrorAsync(unknown), await ErrorAsync(duplicate), await ErrorAsync(unknownPost)));
        Assert.All(new[] { unknown, duplicate, unknownPost }, r => Assert.Null(r.Headers.Location));
    }

    /// <summary>The confirming POST is a cookie-authenticated state change: Origin and antiforgery apply, a Bearer app token is not a session.</summary>
    [Fact]
    public async Task The_logout_confirmation_needs_the_browser_session_and_CSRF_protection()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        OAuthTokenResponse tokens = await AppSessionAsync(browser, spa);
        OAuthLogoutRequest request = new(spa.ClientId, spa.PostLogoutUri, null);

        HttpResponseMessage noXsrf = await PostLogoutAsync(browser, request, sendXsrf: false);
        HttpResponseMessage foreignOrigin = await PostLogoutAsync(browser, request, origin: "https://evil.example.test");
        using Browser bearer = new(app);
        await bearer.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage withAppToken = await PostLogoutAsync(bearer, request, authorization: "Bearer " + tokens.AccessToken);

        Assert.Equal(HttpStatusCode.BadRequest, noXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, foreignOrigin.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, withAppToken.StatusCode);
        await RefreshAsync(spa, tokens.RefreshToken);
    }

    /// <summary>Shared-domain mode: Domain on the access, refresh and XSRF cookies; login, refresh, CSRF and logout work; the old access token is dead.</summary>
    [Fact]
    public async Task Shared_domain_mode_sets_the_domain_and_signs_in_refreshes_and_signs_out()
    {
        await app.DisposeAsync();
        app = WithSettings(new() { ["AuthCookies:Domain"] = "example.test" });
        (_, Browser browser) = await SignedInAsync();
        IReadOnlyList<SetCookie> issued = browser.History.SelectMany(h => SetCookie.From(h.Response)).ToList();

        Assert.Equal("example.test", issued.Last(c => c.Name == AuthCookieNames.AccessWithDomain)["domain"]);
        Assert.Equal("example.test", issued.Last(c => c.Name == AuthCookieNames.Refresh)["domain"]);
        Assert.Equal("example.test", issued.Last(c => c.Name == AuthCookieNames.Xsrf)["domain"]);
        Assert.Null(issued.Last(c => c.Name == AuthCookieNames.Antiforgery)["domain"]);
        Assert.DoesNotContain(issued, c => c.Name == AuthCookieNames.Access);

        HttpResponseMessage refresh = await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh");
        Assert.Equal(HttpStatusCode.NoContent, refresh.StatusCode);
        string oldAccess = browser.CookieValue(AuthCookieNames.AccessWithDomain);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);

        HttpResponseMessage logout = await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/logout");
        IReadOnlyList<SetCookie> cleared = SetCookie.From(logout);

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Contains(cleared, c => c.Name == AuthCookieNames.AccessWithDomain && c.IsExpired && c["domain"] == "example.test" && c["path"] == "/");
        Assert.Contains(cleared, c => c.Name == AuthCookieNames.Refresh && c.IsExpired && c["domain"] == "example.test" && c["path"] == "/api/v1/auth");
        Assert.Contains(cleared, c => c.Name == AuthCookieNames.Access && c.IsExpired && c["domain"] is null);
        Assert.Contains(cleared, c => c.Name == AuthCookieNames.Refresh && c.IsExpired && c["domain"] is null);

        using Browser replay = new(app);
        replay.Plant(AuthCookieNames.AccessWithDomain, oldAccess);
        Assert.Equal(HttpStatusCode.Unauthorized, (await replay.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Host_only_mode_keeps_every_cookie_without_a_domain()
    {
        (_, Browser browser) = await SignedInAsync();
        IReadOnlyList<SetCookie> issued = browser.History.SelectMany(h => SetCookie.From(h.Response)).ToList();

        SetCookie access = issued.Last(c => c.Name == AuthCookieNames.Access);
        Assert.Null(access["domain"]);
        Assert.Equal("/", access["path"]);
        Assert.True(access.HasFlag("secure") && access.HasFlag("httponly"));
        Assert.Null(issued.Last(c => c.Name == AuthCookieNames.Refresh)["domain"]);
        Assert.Null(issued.Last(c => c.Name == AuthCookieNames.Xsrf)["domain"]);
        Assert.DoesNotContain(issued, c => c.Name == AuthCookieNames.AccessWithDomain);

        IReadOnlyList<SetCookie> cleared = SetCookie.From(await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/logout"));
        Assert.All(cleared.Where(c => c.Name is AuthCookieNames.Access or AuthCookieNames.Refresh), c => Assert.Null(c["domain"]));
        Assert.DoesNotContain(cleared, c => c.Name == AuthCookieNames.AccessWithDomain);
    }

    [Theory]
    [InlineData("co.uk")]
    [InlineData(".example.test")]
    [InlineData("other.test")]
    [InlineData("10.0.0.1")]
    [InlineData("Example.test")]
    public void Startup_refuses_a_cookie_domain_that_is_not_a_safe_parent_of_the_auth_host(string domain)
    {
        using WebApplicationFactory<Program> bad = WithSettings(new() { ["AuthCookies:Domain"] = domain });

        Assert.ThrowsAny<Exception>(() => bad.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<Auth.Api.Security.AuthCookieOptions>>().Value);
    }

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> extra)
    {
        Dictionary<string, string?> settings = new(extra)
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:OAuthAuthorize:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:OAuthToken:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:OAuthToken:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:OAuthLogout:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Refresh:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Sessions:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:ChangePassword:PerIp:PermitLimit"] = "1000",
        };
        return api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
            builder.ConfigureTestServices(services => services.AddSingleton<IClock>(clock));
        });
    }

    private static string LogoutUrl(string clientId, string postLogoutUri, string state) =>
        OAuthLogout + "?client_id=" + Uri.EscapeDataString(clientId) + "&post_logout_redirect_uri=" + Uri.EscapeDataString(postLogoutUri) + "&state=" + Uri.EscapeDataString(state);

    private static Task<HttpResponseMessage> PostLogoutAsync(Browser browser, OAuthLogoutRequest request, bool sendXsrf = true, string? origin = null, string? authorization = null) =>
        browser.SendAsync(HttpMethod.Post, OAuthLogout, sendXsrf: sendXsrf, originOverride: origin, configure: r =>
        {
            r.Content = JsonContent.Create(request);
            if (authorization is not null)
            {
                r.Headers.TryAddWithoutValidation("Authorization", authorization);
            }
        });

    private static async Task<string> ErrorAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync())!["error"]!.GetValue<string>();

    private async Task<OAuthTokenResponse> AppSessionAsync(Browser browser, Spa spa)
    {
        string verifier = Base64Url(RandomNumberGenerator.GetBytes(48));
        string challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        HttpResponseMessage authorize = await browser.GetAsync("/api/v1/oauth/authorize?client_id=" + spa.ClientId + "&redirect_uri=" + Uri.EscapeDataString(spa.RedirectUri)
            + "&response_type=code&code_challenge=" + challenge + "&code_challenge_method=S256&state=st");
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        string code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"]!;
        HttpResponseMessage exchange = await TokenAsync(spa, ("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", verifier));
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        return (await exchange.Content.ReadFromJsonAsync<OAuthTokenResponse>())!;
    }

    private async Task<OAuthTokenResponse> RefreshAsync(Spa spa, string refreshToken)
    {
        HttpResponseMessage response = await TokenAsync(spa, ("grant_type", "refresh_token"), ("refresh_token", refreshToken), ("client_id", spa.ClientId));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<OAuthTokenResponse>())!;
    }

    private async Task<string> RefreshErrorAsync(Spa spa, string refreshToken) =>
        await ErrorAsync(await TokenAsync(spa, ("grant_type", "refresh_token"), ("refresh_token", refreshToken), ("client_id", spa.ClientId)));

    private async Task<HttpResponseMessage> TokenAsync(Spa spa, params (string Name, string Value)[] fields)
    {
        using HttpClient client = api.CreateHttpsClient(app);
        using HttpRequestMessage request = new(HttpMethod.Post, "/api/v1/oauth/token")
        {
            Content = new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))),
        };
        request.Headers.TryAddWithoutValidation("Origin", spa.Origin);
        HttpResponseMessage response = await client.SendAsync(request);
        await response.Content.LoadIntoBufferAsync();
        return response;
    }

    private async Task<Spa> RegisterSpaAsync()
    {
        string id = "spa-" + Guid.NewGuid().ToString("N")[..10];
        string origin = "https://" + id + ".example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        ClientApplicationResult result = await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().CreateAsync(
            new ClientApplicationRequest(id, "Spa " + id, "api://" + id, [origin], [origin + "/callback"], [origin + "/signed-out"]),
            true,
            AuditContext.None,
            CancellationToken.None);
        ClientApplicationResponse created = result.Application!;
        return new Spa(created.Id, id, origin, created.RedirectUris[0], created.PostLogoutRedirectUris[0]);
    }

    private async Task<(Guid UserId, Browser Browser)> SignedInAsync()
    {
        string email = "slo-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using (AsyncServiceScope scope = app.Services.CreateAsyncScope())
        {
            string hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
            AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            DateTime now = DateTime.UtcNow;
            User user = new()
            {
                Email = email,
                NormalizedEmail = EmailNormalizer.Normalize(email)!,
                EmailVerified = true,
                PasswordHash = hash,
                DisplayName = "SLO Tester",
                IsActive = true,
                SecurityStamp = Guid.NewGuid(),
                CreatedUtc = now,
                UpdatedUtc = now,
            };
            context.User.Add(user);
            await context.SaveChangesAsync();
        }

        Guid userId = (await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Email == email))).Id;
        return (userId, await LoginAsync(email));
    }

    private async Task<(Guid UserId, Browser Browser)> SignInAgainAsync(Guid userId)
    {
        string email = (await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId))).Email;
        return (userId, await LoginAsync(email));
    }

    private async Task<Browser> LoginAsync(string email)
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage login = await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/login", configure: r =>
            r.Content = new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return browser;
    }

    private async Task<Guid> FamilyOfAsync(Guid userId, Spa spa) =>
        (await QueryAsync(c => c.RefreshToken.AsNoTracking().FirstAsync(t => t.UserId == userId && t.ClientApplicationId == spa.Id && t.RevokedUtc == null))).FamilyId;

    private Task<List<AuditLog>> AuditAsync(Guid userId) => QueryAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record Spa(Guid Id, string ClientId, string Origin, string RedirectUri, string PostLogoutUri);

    private sealed class ShiftableClock : IClock
    {
        private long offsetTicks;

        public DateTime UtcNow => DateTime.UtcNow.AddTicks(Interlocked.Read(ref offsetTicks));

        public void Shift(TimeSpan by) => Interlocked.Add(ref offsetTicks, by.Ticks);
    }
}
