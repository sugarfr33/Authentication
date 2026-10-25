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
using Microsoft.IdentityModel.JsonWebTokens;

namespace Auth.IntegrationTests.Api;

/// <summary>T19 Authorization Code + PKCE through the real host (docs/authorization-code-pkce.md).</summary>
[Collection(ApiTestGroup.Name)]
public sealed class OAuthApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Password = "violet-canyon-7319";
    private const string LoginUrl = "https://login.example.test/signin";
    private const string Authorize = "/api/v1/oauth/authorize";
    private const string Token = "/api/v1/oauth/token";

    private readonly ShiftableClock clock = new();
    private WebApplicationFactory<Program> app = null!;

    public async Task InitializeAsync()
    {
        app = WithSettings(new Dictionary<string, string?>
        {
            ["OAuth:LoginUrl"] = LoginUrl,
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:OAuthAuthorize:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:OAuthToken:PerIp:PermitLimit"] = "1000",
        });
        await Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task The_full_flow_issues_app_tokens_that_refresh_and_detect_reuse_and_never_unlock_this_API()
    {
        Spa spa = await RegisterSpaAsync();
        (Guid userId, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();

        HttpResponseMessage authorize = await browser.GetAsync(AuthorizeUrl(spa, pkce, state: "s-123"));
        Uri location = authorize.Headers.Location!;
        Dictionary<string, string> callback = Query(location);

        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        Assert.StartsWith(spa.RedirectUri + "?", location.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal("s-123", callback["state"]);
        Assert.Equal("no-store", authorize.Headers.CacheControl!.ToString());
        Assert.Contains("no-referrer", authorize.Headers.GetValues("Referrer-Policy"));

        HttpResponseMessage exchange = await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", callback["code"]), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier)));
        OAuthTokenResponse tokens = (await exchange.Content.ReadFromJsonAsync<OAuthTokenResponse>())!;

        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        Assert.Equal("no-store", exchange.Headers.CacheControl!.ToString());
        Assert.Equal(("Bearer", 900), (tokens.Scheme, tokens.ExpiresIn));
        JsonWebToken jwt = new(tokens.AccessToken);
        Assert.Equal([spa.Audience], jwt.Audiences);
        Assert.Equal(spa.ClientId, jwt.GetClaim(AuthClaimTypes.ClientId).Value);
        Assert.Equal(userId.ToString(), jwt.Subject);
        Assert.True(Guid.TryParse(jwt.GetClaim(AuthClaimTypes.SessionId).Value, out _));

        // The app token never works as a session of this API (audience-strict, client_id refused).
        using Browser intruder = new(app);
        await intruder.GetAsync(TestEndpoints.Prefix + "/ping");
        intruder.Plant(AuthCookieNames.Access, tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await intruder.GetAsync("/api/v1/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await intruder.GetAsync(TestEndpoints.Prefix + "/policy/" + AuthPolicies.AdminRole)).StatusCode);

        // Refresh rotates; presenting the old refresh token again is reuse and ends the family.
        HttpResponseMessage refreshed = await TokenAsync(spa.Origin, Form(("grant_type", "refresh_token"), ("refresh_token", tokens.RefreshToken), ("client_id", spa.ClientId)));
        OAuthTokenResponse next = (await refreshed.Content.ReadFromJsonAsync<OAuthTokenResponse>())!;
        clock.Shift(TimeSpan.FromSeconds(11));
        HttpResponseMessage reused = await TokenAsync(spa.Origin, Form(("grant_type", "refresh_token"), ("refresh_token", tokens.RefreshToken), ("client_id", spa.ClientId)));
        HttpResponseMessage afterReuse = await TokenAsync(spa.Origin, Form(("grant_type", "refresh_token"), ("refresh_token", next.RefreshToken), ("client_id", spa.ClientId)));

        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.NotEqual(tokens.RefreshToken, next.RefreshToken);
        Assert.Equal("invalid_grant", await ErrorAsync(reused));
        Assert.Equal("invalid_grant", await ErrorAsync(afterReuse));

        // Audit: issued and redeemed, ids only.
        List<AuditLog> rows = await QueryAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());
        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.AuthorizationCodeIssued));
        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.AuthorizationCodeRedeemed));
        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.TokenReuse));
    }

    /// <summary>No open redirect: until the redirect URI is an exact registered string, errors stay on our domain.</summary>
    [Theory]
    [InlineData("https://evil.example.test/callback")]
    [InlineData("{0}/extra")]
    [InlineData("{0}/")]
    [InlineData("{0}?next=1")]
    [InlineData("{0}#fragment")]
    [InlineData("UPPER")]
    [InlineData("USERINFO")]
    [InlineData("HTTP")]
    [InlineData("ENCODED")]
    [InlineData("")]
    public async Task An_unregistered_or_altered_redirect_uri_never_redirects(string variant)
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        string host = new Uri(spa.RedirectUri).Host;
        string redirect = variant switch
        {
            "UPPER" => spa.RedirectUri.Replace(host, host.ToUpperInvariant(), StringComparison.Ordinal),
            "USERINFO" => spa.RedirectUri.Replace("https://", "https://user@", StringComparison.Ordinal),
            "HTTP" => spa.RedirectUri.Replace("https://", "http://", StringComparison.Ordinal),
            "ENCODED" => spa.RedirectUri.Replace("/callback", "/%63allback", StringComparison.Ordinal),
            _ => string.Format(System.Globalization.CultureInfo.InvariantCulture, variant, spa.RedirectUri),
        };

        HttpResponseMessage response = await browser.GetAsync(AuthorizeUrl(spa, Pkce.Create(), redirectUri: redirect));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("invalid_redirect_uri", await ErrorAsync(response));
    }

    [Fact]
    public async Task Unknown_or_inactive_clients_and_duplicate_parameters_never_redirect()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();

        HttpResponseMessage unknown = await browser.GetAsync(AuthorizeUrl(spa with { ClientId = "no-such-client" }, pkce));
        HttpResponseMessage duplicate = await browser.GetAsync(AuthorizeUrl(spa, pkce) + "&redirect_uri=" + Uri.EscapeDataString("https://evil.example.test/cb"));
        await DeactivateAsync(spa);
        HttpResponseMessage inactive = await browser.GetAsync(AuthorizeUrl(spa, pkce));

        foreach (HttpResponseMessage response in new[] { unknown, duplicate, inactive })
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Null(response.Headers.Location);
        }

        Assert.Equal(("invalid_client", "invalid_request", "invalid_client"), (await ErrorAsync(unknown), await ErrorAsync(duplicate), await ErrorAsync(inactive)));
    }

    /// <summary>Once the redirect URI is trusted, request errors go back to it with an error code (and the state).</summary>
    [Theory]
    [InlineData("method=plain", "invalid_request", true)]
    [InlineData("method=", "invalid_request", true)]
    [InlineData("challenge=short", "invalid_request", true)]
    [InlineData("response_type=token", "unsupported_response_type", true)]
    [InlineData("state=", "invalid_request", false)]
    public async Task Request_errors_after_redirect_validation_are_redirected_with_the_error(string change, string error, bool stateEchoed)
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string url = change switch
        {
            "method=plain" => AuthorizeUrl(spa, pkce, method: "plain"),
            "method=" => AuthorizeUrl(spa, pkce, method: null),
            "challenge=short" => AuthorizeUrl(spa, pkce with { Challenge = "abc" }),
            "response_type=token" => AuthorizeUrl(spa, pkce, responseType: "token"),
            _ => AuthorizeUrl(spa, pkce, state: null),
        };

        HttpResponseMessage response = await browser.GetAsync(url);
        Dictionary<string, string> callback = Query(response.Headers.Location!);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(spa.RedirectUri + "?", response.Headers.Location!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal(error, callback["error"]);
        Assert.Equal(stateEchoed, callback.ContainsKey("state"));
        Assert.False(callback.ContainsKey("code"));
    }

    [Fact]
    public async Task Without_a_session_the_user_is_sent_to_the_login_UI_with_a_relative_return_path()
    {
        Spa spa = await RegisterSpaAsync();
        using Browser anonymous = new(app);
        string url = AuthorizeUrl(spa, Pkce.Create());

        HttpResponseMessage response = await anonymous.GetAsync(url);
        Uri location = response.Headers.Location!;
        string returnTo = Query(location)["returnTo"];

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(LoginUrl + "?returnTo=", location.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal(url, returnTo);
        Assert.StartsWith(Authorize + "?", returnTo, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_code_is_single_use_and_a_replay_revokes_the_session_it_started()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string code = await CodeAsync(browser, spa, pkce);
        FormUrlEncodedContent Exchange() => Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier));

        OAuthTokenResponse first = (await (await TokenAsync(spa.Origin, Exchange())).Content.ReadFromJsonAsync<OAuthTokenResponse>())!;
        HttpResponseMessage replay = await TokenAsync(spa.Origin, Exchange());
        HttpResponseMessage refreshAfterReplay = await TokenAsync(spa.Origin, Form(("grant_type", "refresh_token"), ("refresh_token", first.RefreshToken), ("client_id", spa.ClientId)));

        Assert.Equal("invalid_grant", await ErrorAsync(replay));
        Assert.Equal("invalid_grant", await ErrorAsync(refreshAfterReplay));
        Assert.Contains(await RejectionsAsync(spa), r => r.Detail!.Contains("\"replayed\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_code_expires_after_60_seconds()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string code = await CodeAsync(browser, spa, pkce);

        clock.Shift(TimeSpan.FromSeconds(61));
        HttpResponseMessage late = await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier)));

        Assert.Equal("invalid_grant", await ErrorAsync(late));
    }

    /// <summary>Wrong verifier, client or redirect URI all give the same invalid_grant, and burn the code.</summary>
    [Theory]
    [InlineData("verifier")]
    [InlineData("client")]
    [InlineData("redirect")]
    public async Task A_code_is_bound_to_its_verifier_client_and_redirect_uri_and_burned_by_a_failed_exchange(string swap)
    {
        Spa spa = await RegisterSpaAsync();
        Spa other = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string code = await CodeAsync(browser, spa, pkce);
        (string origin, string clientId, string redirect, string verifier) = swap switch
        {
            "verifier" => (spa.Origin, spa.ClientId, spa.RedirectUri, Pkce.Create().Verifier),
            "client" => (other.Origin, other.ClientId, spa.RedirectUri, pkce.Verifier),
            _ => (spa.Origin, spa.ClientId, spa.SecondRedirectUri, pkce.Verifier),
        };

        HttpResponseMessage wrong = await TokenAsync(origin, Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect), ("client_id", clientId), ("code_verifier", verifier)));
        HttpResponseMessage rightAfterwards = await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier)));

        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal("invalid_grant", await ErrorAsync(wrong));
        Assert.Equal("invalid_grant", await ErrorAsync(rightAfterwards));
    }

    [Fact]
    public async Task The_code_belongs_to_the_user_who_authorized_it()
    {
        Spa spa = await RegisterSpaAsync();
        (Guid alice, Browser aliceBrowser) = await SignedInAsync();
        (Guid bob, _) = await SignedInAsync();
        Pkce pkce = Pkce.Create();

        string code = await CodeAsync(aliceBrowser, spa, pkce);
        OAuthTokenResponse tokens = (await (await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier)))).Content.ReadFromJsonAsync<OAuthTokenResponse>())!;

        Assert.NotEqual(alice, bob);
        Assert.Equal(alice.ToString(), new JsonWebToken(tokens.AccessToken).Subject);
    }

    [Fact]
    public async Task The_token_endpoint_requires_the_clients_own_origin_and_a_form_body()
    {
        Spa spa = await RegisterSpaAsync();
        Spa other = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string code = await CodeAsync(browser, spa, pkce);
        FormUrlEncodedContent Exchange() => Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier));

        HttpResponseMessage foreignOrigin = await TokenAsync(other.Origin, Exchange());
        HttpResponseMessage json = await TokenAsync(spa.Origin, new StringContent(JsonSerializer.Serialize(new { grant_type = "authorization_code", code }), Encoding.UTF8, "application/json"));
        HttpResponseMessage stillValid = await TokenAsync(spa.Origin, Exchange());

        Assert.Equal("invalid_client", await ErrorAsync(foreignOrigin));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, json.StatusCode);
        Assert.Equal(HttpStatusCode.OK, stillValid.StatusCode);
    }

    [Fact]
    public async Task A_deactivated_application_cannot_exchange_its_codes()
    {
        Spa spa = await RegisterSpaAsync();
        (_, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string code = await CodeAsync(browser, spa, pkce);
        await DeactivateAsync(spa);

        HttpResponseMessage exchange = await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", pkce.Verifier)));

        // Refused at the origin check (its origins left the CORS list) or by the exchange itself: never tokens.
        Assert.Contains(exchange.StatusCode, new[] { HttpStatusCode.BadRequest, HttpStatusCode.Forbidden });
        Assert.DoesNotContain("access_token", await exchange.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Codes_verifiers_and_tokens_never_reach_logs_or_audit_rows()
    {
        Spa spa = await RegisterSpaAsync();
        (Guid userId, Browser browser) = await SignedInAsync();
        Pkce pkce = Pkce.Create();
        string code = await CodeAsync(browser, spa, pkce, state: "state-secret-77");
        await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", "x" + pkce.Verifier[1..])));
        Pkce second = Pkce.Create();
        string code2 = await CodeAsync(browser, spa, second);
        OAuthTokenResponse tokens = (await (await TokenAsync(spa.Origin, Form(("grant_type", "authorization_code"), ("code", code2), ("redirect_uri", spa.RedirectUri), ("client_id", spa.ClientId), ("code_verifier", second.Verifier)))).Content.ReadFromJsonAsync<OAuthTokenResponse>())!;

        string[] secrets = [code, code2, pkce.Verifier, second.Verifier, pkce.Challenge, tokens.AccessToken, tokens.RefreshToken, "state-secret-77"];
        List<AuditLog> rows = await QueryAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());
        string audit = string.Join("|", rows.Select(r => r.Detail + r.UserAgent + r.IpAddress + r.CorrelationId));
        IReadOnlyList<string> logs = api.Logs.Texts;

        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.AuthorizationCodeRejected) && r.Detail!.Contains("pkce_mismatch", StringComparison.Ordinal));
        Assert.All(secrets, secret => Assert.DoesNotContain(secret, audit, StringComparison.Ordinal));
        Assert.All(secrets, secret => Assert.DoesNotContain(logs, line => line.Contains(secret, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task The_token_endpoint_is_rate_limited_per_ip()
    {
        await using WebApplicationFactory<Program> limited = WithSettings(new Dictionary<string, string?>
        {
            ["OAuth:LoginUrl"] = LoginUrl,
            ["RateLimiting:Policies:OAuthToken:PerIp:PermitLimit"] = "2",
        });
        using HttpClient client = api.CreateHttpsClient(limited);

        List<HttpStatusCode> statuses = [];
        for (int i = 0; i < 3; i++)
        {
            using HttpRequestMessage request = new(HttpMethod.Post, Token) { Content = Form(("grant_type", "authorization_code"), ("client_id", "x")) };
            request.Headers.TryAddWithoutValidation("Origin", ApiFixture.AppOrigin);
            statuses.Add((await client.SendAsync(request)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[^1]);
    }

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> settings) => api.Factory.WithWebHostBuilder(builder =>
    {
        foreach (KeyValuePair<string, string?> setting in settings)
        {
            builder.UseSetting(setting.Key, setting.Value);
        }

        builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        builder.ConfigureTestServices(services => services.AddSingleton<IClock>(clock));
    });

    private static string AuthorizeUrl(Spa spa, Pkce pkce, string? redirectUri = null, string? state = "st", string? method = "S256", string responseType = "code")
    {
        List<string> parts =
        [
            "client_id=" + Uri.EscapeDataString(spa.ClientId),
            "redirect_uri=" + Uri.EscapeDataString(redirectUri ?? spa.RedirectUri),
            "response_type=" + responseType,
            "code_challenge=" + Uri.EscapeDataString(pkce.Challenge),
        ];
        if (method is not null)
        {
            parts.Add("code_challenge_method=" + method);
        }

        if (state is not null)
        {
            parts.Add("state=" + Uri.EscapeDataString(state));
        }

        return Authorize + "?" + string.Join("&", parts);
    }

    private static Dictionary<string, string> Query(Uri uri) =>
        Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query).ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal);

    private static FormUrlEncodedContent Form(params (string Name, string Value)[] fields) =>
        new(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value)));

    private static async Task<string> ErrorAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync())!["error"]!.GetValue<string>();

    private static async Task<string> CodeAsync(Browser browser, Spa spa, Pkce pkce, string state = "st")
    {
        HttpResponseMessage response = await browser.GetAsync(AuthorizeUrl(spa, pkce, state: state));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return Query(response.Headers.Location!)["code"];
    }

    private async Task<HttpResponseMessage> TokenAsync(string origin, HttpContent content)
    {
        using HttpClient client = api.CreateHttpsClient(app);
        using HttpRequestMessage request = new(HttpMethod.Post, Token) { Content = content };
        request.Headers.TryAddWithoutValidation("Origin", origin);
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
            new ClientApplicationRequest(id, "Spa " + id, "api://" + id, [origin], [origin + "/callback", origin + "/other-callback"], []),
            true,
            AuditContext.None,
            CancellationToken.None);
        ClientApplicationResponse created = result.Application!;
        return new Spa(created.Id, id, origin, created.RedirectUris[0], created.RedirectUris[1], created.Audience);
    }

    private async Task DeactivateAsync(Spa spa)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().DeactivateAsync(spa.Id, AuditContext.None, CancellationToken.None);
    }

    private Task<List<AuditLog>> RejectionsAsync(Spa spa)
    {
        string id = spa.Id.ToString("D");
        return QueryAsync(c => c.AuditLog.AsNoTracking().Where(a => a.EventType == nameof(AuditEventType.AuthorizationCodeRejected) && a.Detail!.Contains(id)).ToListAsync());
    }

    private async Task<(Guid UserId, Browser Browser)> SignedInAsync()
    {
        string email = "oauth-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        Guid userId;
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
                DisplayName = "OAuth Tester",
                IsActive = true,
                SecurityStamp = Guid.NewGuid(),
                CreatedUtc = now,
                UpdatedUtc = now,
            };
            context.User.Add(user);
            await context.SaveChangesAsync();
            userId = user.Id;
        }

        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage login = await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/login", configure: r =>
            r.Content = new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return (userId, browser);
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private sealed record Spa(Guid Id, string ClientId, string Origin, string RedirectUri, string SecondRedirectUri, string Audience);

    private sealed record Pkce(string Verifier, string Challenge)
    {
        public static Pkce Create()
        {
            string verifier = Base64Url(RandomNumberGenerator.GetBytes(48));
            return new Pkce(verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
        }

        private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Real time plus an adjustable offset (code expiry).</summary>
    private sealed class ShiftableClock : IClock
    {
        private long offsetTicks;

        public DateTime UtcNow => DateTime.UtcNow.AddTicks(Interlocked.Read(ref offsetTicks));

        public void Shift(TimeSpan by) => Interlocked.Add(ref offsetTicks, by.Ticks);
    }
}
