using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Auth.Contracts;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Api;

/// <summary>T10 through WebApplicationFactory: cookie transport, CSRF, Origin checks, CORS and the cookie auth handler.</summary>
[Collection(ApiTestGroup.Name)]
public sealed partial class CookieAuthTests(ApiFixture api)
{
    private const string Me = TestEndpoints.Prefix + "/me";
    private const string Echo = TestEndpoints.Prefix + "/echo";
    private const string Protected = TestEndpoints.Prefix + "/protected";

    public static TheoryData<string> StateChangingMethods => new() { "POST", "PUT", "PATCH", "DELETE" };

    // ---------- Cookie transport ----------

    [Fact]
    public async Task Session_cookies_are_HttpOnly_Secure_prefixed_scoped_and_short_lived()
    {
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        HttpResponseMessage session = await browser.SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/session");

        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        IReadOnlyList<SetCookie> cookies = SetCookie.From(session);
        SetCookie access = Assert.Single(cookies, c => c.Name == AuthCookieNames.Access);
        Assert.True(access.HasFlag("httponly"));
        Assert.True(access.HasFlag("secure"));
        Assert.Equal("lax", access["samesite"]);
        Assert.Equal("/", access["path"]);
        Assert.Null(access["domain"]);
        Assert.InRange(int.Parse(access["max-age"]!, System.Globalization.CultureInfo.InvariantCulture), 890, 900);

        SetCookie refresh = Assert.Single(cookies, c => c.Name == AuthCookieNames.Refresh);
        Assert.True(refresh.HasFlag("httponly"));
        Assert.True(refresh.HasFlag("secure"));
        Assert.Equal("strict", refresh["samesite"]);
        Assert.Equal("/api/v1/auth", refresh["path"]);
        Assert.Null(refresh["domain"]);
        Assert.InRange(int.Parse(refresh["max-age"]!, System.Globalization.CultureInfo.InvariantCulture), 1_209_590, 1_209_600);
    }

    [Fact]
    public async Task The_access_cookie_authenticates_and_anonymous_requests_get_401()
    {
        using Browser anonymous = new(api.Factory);
        HttpResponseMessage denied = await anonymous.GetAsync(Me);
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Equal("application/problem+json", denied.Content.Headers.ContentType?.MediaType);

        using Browser browser = new(api.Factory);
        await browser.SignInAsync();
        HttpResponseMessage me = await browser.GetAsync(Me);

        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
        Assert.Equal(ApiFixture.UserId.ToString(), body.RootElement.GetProperty("sub").GetString());
        Assert.True(body.RootElement.GetProperty("isUser").GetBoolean());
        Assert.Equal("Api User", body.RootElement.GetProperty("name").GetString());
    }

    [Fact]
    public async Task A_configured_domain_switches_the_access_cookie_to_Secure_prefix_with_Domain()
    {
        await using WebApplicationFactory<Program> shared = WithSettings(new() { ["AuthCookies:Domain"] = "example.test" });
        using Browser browser = new(shared);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        IReadOnlyList<SetCookie> cookies = SetCookie.From(await browser.SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/session"));

        SetCookie access = Assert.Single(cookies, c => c.Name == AuthCookieNames.AccessWithDomain);
        Assert.Equal("example.test", access["domain"]);
        Assert.DoesNotContain(cookies, c => c.Name == AuthCookieNames.Access && !c.IsExpired);
        Assert.Equal("example.test", Assert.Single(cookies, c => c.Name == AuthCookieNames.Refresh && !c.IsExpired)["domain"]);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task Logout_expires_both_cookies_with_the_same_attributes()
    {
        using Browser browser = new(api.Factory);
        IReadOnlyList<SetCookie> issued = SetCookie.From(await browser.SignInAsync());

        HttpResponseMessage logout = await browser.SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/logout");

        IReadOnlyList<SetCookie> cleared = SetCookie.From(logout);
        foreach (string name in new[] { AuthCookieNames.Access, AuthCookieNames.Refresh })
        {
            SetCookie before = issued.Single(c => c.Name == name);
            SetCookie after = Assert.Single(cleared, c => c.Name == name);
            Assert.True(after.IsExpired);
            Assert.Equal(string.Empty, after.Value);
            Assert.Equal(before["path"], after["path"]);
            Assert.Equal(before["samesite"], after["samesite"]);
            Assert.Equal(before["domain"], after["domain"]);
            Assert.True(after.HasFlag("httponly") && after.HasFlag("secure"));
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task No_token_appears_in_any_response_body_or_script_readable_header()
    {
        using Browser browser = new(api.Factory);
        await browser.SignInAsync();
        string access = browser.CookieValue(AuthCookieNames.Access);
        await browser.GetAsync(Me);
        await browser.SendAsync(HttpMethod.Post, Protected);
        await browser.GetAsync("/.well-known/jwks.json");
        string refresh = (await RefreshValueAsync()) ?? string.Empty;

        Assert.Matches(JwtPattern(), access);
        foreach ((HttpResponseMessage response, string body) in browser.History)
        {
            Assert.DoesNotMatch(JwtPattern(), body);
            Assert.DoesNotContain(access, body, StringComparison.Ordinal);
            IEnumerable<string> headerValues = response.Headers.Where(h => h.Key != "Set-Cookie").Concat(response.Content.Headers).SelectMany(h => h.Value);
            Assert.DoesNotContain(headerValues, v => JwtPattern().IsMatch(v));
            Assert.DoesNotContain("access", response.RequestMessage!.RequestUri!.Query, StringComparison.OrdinalIgnoreCase);
        }

        Assert.All(browser.History, h => Assert.DoesNotContain(refresh.Length > 0 ? refresh : "\u0000", h.Body, StringComparison.Ordinal));

        async Task<string?> RefreshValueAsync()
        {
            using Browser other = new(api.Factory);
            return SetCookie.From(await other.SignInAsync()).SingleOrDefault(c => c.Name == AuthCookieNames.Refresh)?.Value;
        }
    }

    // ---------- Antiforgery ----------

    [Fact]
    public async Task GET_issues_a_readable_XSRF_cookie_and_an_HttpOnly_antiforgery_cookie()
    {
        using Browser browser = new(api.Factory);

        IReadOnlyList<SetCookie> cookies = SetCookie.From(await browser.GetAsync(TestEndpoints.Prefix + "/ping"));

        SetCookie xsrf = Assert.Single(cookies, c => c.Name == AuthCookieNames.Xsrf);
        Assert.False(xsrf.HasFlag("httponly"));
        Assert.True(xsrf.HasFlag("secure"));
        Assert.Equal("strict", xsrf["samesite"]);
        SetCookie antiforgery = Assert.Single(cookies, c => c.Name == AuthCookieNames.Antiforgery);
        Assert.True(antiforgery.HasFlag("httponly"));
        Assert.True(antiforgery.HasFlag("secure"));
    }

    [Theory]
    [MemberData(nameof(StateChangingMethods))]
    public async Task State_changing_requests_need_a_matching_XSRF_header(string method)
    {
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        HttpResponseMessage missing = await browser.SendAsync(new HttpMethod(method), Echo, sendXsrf: false);
        HttpResponseMessage wrong = await browser.SendAsync(new HttpMethod(method), Echo, xsrfOverride: "not-the-token");
        HttpResponseMessage ok = await browser.SendAsync(new HttpMethod(method), Echo);

        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal("application/problem+json", missing.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Antiforgery_tokens_are_bound_to_the_user_and_are_reissued_after_sign_in()
    {
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        string anonymousToken = browser.Xsrf!;
        await browser.SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/session");

        HttpResponseMessage stale = await browser.SendAsync(HttpMethod.Post, Protected, xsrfOverride: anonymousToken);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage fresh = await browser.SendAsync(HttpMethod.Post, Protected);

        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }

    // ---------- Origin / Referer ----------

    [Theory]
    [InlineData("https://evil.example.test")]
    [InlineData(ApiFixture.InactiveOrigin)]
    [InlineData("null")]
    [InlineData("https://app.example.test.evil.test")]
    [InlineData("http://app.example.test")]
    public async Task State_changing_request_from_a_disallowed_origin_is_403(string origin)
    {
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, Echo, originOverride: origin);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Missing_Origin_and_Referer_is_403_unless_explicitly_allowed()
    {
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(HttpMethod.Post, Echo, sendOrigin: false)).StatusCode);

        await using WebApplicationFactory<Program> lenient = WithSettings(new() { ["BrowserProtection:AllowMissingOrigin"] = "true" }, Environments.Development);
        using Browser cli = new(lenient);
        await cli.GetAsync(TestEndpoints.Prefix + "/ping");
        Assert.Equal(HttpStatusCode.OK, (await cli.SendAsync(HttpMethod.Post, Echo, sendOrigin: false)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await cli.SendAsync(HttpMethod.Post, Echo, sendOrigin: false, sendXsrf: false)).StatusCode);
    }

    [Fact]
    public async Task Referer_is_the_fallback_and_same_origin_and_trusted_origins_are_allowed()
    {
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(HttpMethod.Post, Echo, sendOrigin: false, referer: ApiFixture.AppOrigin + "/settings")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(HttpMethod.Post, Echo, sendOrigin: false, referer: "https://evil.example.test/page")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(HttpMethod.Post, Echo, originOverride: "https://" + ApiFixture.Host)).StatusCode);

        await using WebApplicationFactory<Program> withUi = WithSettings(new() { ["BrowserProtection:TrustedOrigins:0"] = "https://login.example.test" });
        using Browser ui = new(withUi, "https://login.example.test");
        await ui.GetAsync(TestEndpoints.Prefix + "/ping");
        Assert.Equal(HttpStatusCode.OK, (await ui.SendAsync(HttpMethod.Post, Echo)).StatusCode);
    }

    // ---------- CORS ----------

    [Fact]
    public async Task Preflight_from_an_allowed_origin_lists_exactly_that_origin_with_credentials()
    {
        using HttpClient client = api.CreateHttpsClient();
        using HttpRequestMessage preflight = Preflight(ApiFixture.AppOrigin);

        HttpResponseMessage response = await client.SendAsync(preflight);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(ApiFixture.AppOrigin, response.Header("Access-Control-Allow-Origin"));
        Assert.Equal("true", response.Header("Access-Control-Allow-Credentials"));
        Assert.Contains("POST", response.Header("Access-Control-Allow-Methods"), StringComparison.Ordinal);
        Assert.Contains(AuthCookieNames.XsrfHeader, response.Header("Access-Control-Allow-Headers"), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://evil.example.test")]
    [InlineData(ApiFixture.InactiveOrigin)]
    public async Task Unknown_or_inactive_origins_get_no_CORS_headers(string origin)
    {
        using HttpClient client = api.CreateHttpsClient();
        using HttpRequestMessage preflight = Preflight(origin);
        using HttpRequestMessage simple = new(HttpMethod.Get, TestEndpoints.Prefix + "/ping");
        simple.Headers.TryAddWithoutValidation("Origin", origin);

        HttpResponseMessage preflightResponse = await client.SendAsync(preflight);
        HttpResponseMessage simpleResponse = await client.SendAsync(simple);

        Assert.False(preflightResponse.HasHeader("Access-Control-Allow-Origin"));
        Assert.False(simpleResponse.HasHeader("Access-Control-Allow-Origin"));
        Assert.False(simpleResponse.HasHeader("Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task Credentialed_CORS_never_uses_a_wildcard()
    {
        using HttpClient client = api.CreateHttpsClient();
        foreach (string origin in new[] { ApiFixture.AppOrigin, "https://evil.example.test", "*", "null" })
        {
            using HttpRequestMessage request = new(HttpMethod.Get, TestEndpoints.Prefix + "/ping");
            request.Headers.TryAddWithoutValidation("Origin", origin);
            HttpResponseMessage response = await client.SendAsync(request);

            Assert.NotEqual("*", response.Header("Access-Control-Allow-Origin"));
            if (response.HasHeader("Access-Control-Allow-Origin"))
            {
                Assert.Equal(ApiFixture.AppOrigin, response.Header("Access-Control-Allow-Origin"));
                Assert.Equal("true", response.Header("Access-Control-Allow-Credentials"));
                Assert.Contains("Origin", response.Header("Vary"), StringComparison.Ordinal);
            }
        }
    }

    // ---------- Authentication handler: the T07 attack matrix over HTTP ----------

    [Fact]
    public async Task A_correctly_signed_token_in_the_cookie_is_accepted()
    {
        SecurityTokenDescriptor descriptor = ValidDescriptor();
        descriptor.Claims[AuthClaimTypes.SessionId] = (await LiveSessionAsync()).ToString();

        HttpResponseMessage response = await GetMeWithCookieAsync(Sign(descriptor));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>Prerequisite 2 (T16): a correctly signed token is refused without a live session (no sid, or an unknown one).</summary>
    [Fact]
    public async Task A_correctly_signed_token_without_a_live_session_gets_401()
    {
        SecurityTokenDescriptor unknownSession = ValidDescriptor();
        unknownSession.Claims[AuthClaimTypes.SessionId] = Guid.NewGuid().ToString();

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetMeWithCookieAsync(Sign(ValidDescriptor()))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GetMeWithCookieAsync(Sign(unknownSession))).StatusCode);
    }

    /// <summary>A fresh refresh family for the seeded user, so a hand-signed token can name a live session.</summary>
    private async Task<Guid> LiveSessionAsync()
    {
        await using AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope();
        IRefreshTokenService refresh = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
        return (await refresh.IssueAsync(ApiFixture.UserId, null, new RefreshContext("203.0.113.1", "cookie-tests"), CancellationToken.None)).FamilyId;
    }

    [Fact]
    public async Task Forged_expired_and_misdirected_tokens_get_401()
    {
        SecurityTokenDescriptor none = ValidDescriptor();
        none.SigningCredentials = null;

        SecurityTokenDescriptor hs256 = ValidDescriptor();
        hs256.SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(PublicKeyBytes()) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.HmacSha256);

        SecurityTokenDescriptor expired = ValidDescriptor();
        expired.IssuedAt = expired.NotBefore = DateTime.UtcNow.AddHours(-2);
        expired.Expires = DateTime.UtcNow.AddHours(-1);

        SecurityTokenDescriptor wrongAudience = ValidDescriptor();
        wrongAudience.Audience = "api://someone-else";

        SecurityTokenDescriptor wrongIssuer = ValidDescriptor();
        wrongIssuer.Issuer = "https://evil.example.test";

        using ECDsa attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SecurityTokenDescriptor wrongKey = ValidDescriptor();
        wrongKey.SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(attacker) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.EcdsaSha256);

        string[] forged =
        [
            new JsonWebTokenHandler().CreateToken(none),
            new JsonWebTokenHandler().CreateToken(hs256),
            Sign(expired),
            Sign(wrongAudience),
            Sign(wrongIssuer),
            new JsonWebTokenHandler().CreateToken(wrongKey),
            "not-a-jwt",
            new string('a', 9000),
        ];

        foreach (string token in forged)
        {
            HttpResponseMessage response = await GetMeWithCookieAsync(token);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        }
    }

    [Fact]
    public async Task A_valid_token_in_the_Authorization_header_is_ignored_cookie_only()
    {
        using HttpClient client = api.Factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://" + ApiFixture.Host), HandleCookies = false });
        using HttpRequestMessage request = new(HttpMethod.Get, Me);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Sign(ValidDescriptor()));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(request)).StatusCode);
    }

    private static HttpRequestMessage Preflight(string origin)
    {
        HttpRequestMessage request = new(HttpMethod.Options, Echo);
        request.Headers.TryAddWithoutValidation("Origin", origin);
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "content-type, x-xsrf-token");
        return request;
    }

    private async Task<HttpResponseMessage> GetMeWithCookieAsync(string token)
    {
        using HttpClient client = api.Factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://" + ApiFixture.Host), HandleCookies = false });
        using HttpRequestMessage request = new(HttpMethod.Get, Me);
        request.Headers.TryAddWithoutValidation("Cookie", AuthCookieNames.Access + "=" + token);
        return await client.SendAsync(request);
    }

    private SecurityTokenDescriptor ValidDescriptor() => new()
    {
        Issuer = ApiFixture.Issuer,
        Audience = ApiFixture.Issuer,
        IssuedAt = DateTime.UtcNow,
        NotBefore = DateTime.UtcNow,
        Expires = DateTime.UtcNow.AddMinutes(15),
        TokenType = "at+jwt",
        Claims = new Dictionary<string, object> { [AuthClaimTypes.Subject] = ApiFixture.UserId.ToString(), [AuthClaimTypes.Role] = new[] { "User" } },
        SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(SigningKey()) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.EcdsaSha256),
    };

    private static string Sign(SecurityTokenDescriptor descriptor) => new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);

    private ECDsa SigningKey()
    {
        ECDsa key = ECDsa.Create();
        key.ImportFromPem(api.PrivateKeyPem);
        return key;
    }

    private byte[] PublicKeyBytes()
    {
        using ECDsa key = SigningKey();
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return [.. parameters.Q.X!, .. parameters.Q.Y!];
    }

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> settings, string? environment = null) => api.Factory.WithWebHostBuilder(builder =>
    {
        if (environment is not null)
        {
            builder.UseEnvironment(environment);
        }

        foreach (KeyValuePair<string, string?> setting in settings)
        {
            builder.UseSetting(setting.Key, setting.Value);
        }

        builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
    });

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")]
    private static partial Regex JwtPattern();
}
