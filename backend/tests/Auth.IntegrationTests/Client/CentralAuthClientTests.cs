using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Auth.Client;
using Auth.Contracts;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.Api;
using Auth.SampleApi;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Client;

/// <summary>
/// T22: the sample API (Auth.Client's AddCentralAuth) against the real central auth, whose TestServer serves the JWKS.
/// The sample has no secret and no database: it trusts the published keys only (docs/t22-client-extension.md).
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class CentralAuthClientTests(ApiFixture api) : IAsyncLifetime
{
    private const string ClientId = "active-app";
    private const string AppAudience = "api://" + ClientId;
    private const string Reader = "app:" + ClientId + ":" + SampleApiProgram.ReaderRole;

    private readonly SharedClock clock = new();
    private readonly List<IAsyncDisposable> hosts = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (IAsyncDisposable host in hosts)
        {
            await host.DisposeAsync();
        }
    }

    [Fact]
    public async Task A_valid_application_token_is_accepted_through_the_JWKS_only()
    {
        HttpClient sample = Sample(new JwksSource(api.Factory.Server.CreateHandler()));
        string token = await MintAsync(api.Factory, AppAudience, ClientId, [Reader]);
        string withoutRole = await MintAsync(api.Factory, AppAudience, ClientId, []);

        HttpResponseMessage anonymous = await sample.GetAsync("/health");
        HttpResponseMessage noToken = await sample.GetAsync("/api/me");
        HttpResponseMessage me = await GetAsync(sample, "/api/me", token);
        HttpResponseMessage reports = await GetAsync(sample, "/api/reports", token);
        HttpResponseMessage forbidden = await GetAsync(sample, "/api/reports", withoutRole);

        Assert.Equal(HttpStatusCode.OK, anonymous.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, noToken.StatusCode);
        Assert.Equal("Bearer", noToken.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        SampleMeResponse body = (await me.Content.ReadFromJsonAsync<SampleMeResponse>())!;
        Assert.Equal((ApiFixture.UserId.ToString(), "Sample User"), (body.Subject, body.Name));
        Assert.Contains(Reader, body.Roles);
        Assert.Equal(HttpStatusCode.OK, reports.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
    }

    [Fact]
    public async Task Forged_expired_misdirected_and_wrong_algorithm_tokens_are_refused()
    {
        HttpClient sample = Sample(new JwksSource(api.Factory.Server.CreateHandler()));
        using ECDsa real = ECDsa.Create();
        real.ImportFromPem(api.PrivateKeyPem);
        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RSA rsa = RSA.Create(2048);
        DateTime now = DateTime.UtcNow;

        Dictionary<string, string> refused = new()
        {
            ["forged (other key, real kid)"] = Sign(new ECDsaSecurityKey(other) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.EcdsaSha256, d => { }),
            ["expired"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => (d.IssuedAt, d.NotBefore, d.Expires) = (now.AddHours(-2), now.AddHours(-2), now.AddHours(-1))),
            ["not yet valid"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => (d.IssuedAt, d.NotBefore, d.Expires) = (now, now.AddHours(1), now.AddHours(2))),
            ["no expiry"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => (d.IssuedAt, d.NotBefore, d.Expires) = (null, null, null)),
            ["wrong audience"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => d.Audience = "api://insecure-app"),
            ["wrong issuer"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => d.Issuer = "https://evil.example.test"),
            ["wrong client_id"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => d.Claims![AuthClaimTypes.ClientId] = "insecure-app"),
            ["no client_id (browser token)"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => d.Claims!.Remove(AuthClaimTypes.ClientId)),
            ["wrong typ"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => d.TokenType = "JWT"),
            ["no subject"] = Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => d.Claims!.Remove(AuthClaimTypes.Subject)),
            ["alg none"] = Unsigned(),
            ["HS256 keyed with the public key"] = Sign(
                new SymmetricSecurityKey(real.ExportSubjectPublicKeyInfo()) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.HmacSha256, d => { }),
            ["RS256 under the ES256 kid"] = Sign(new RsaSecurityKey(rsa) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.RsaSha256, d => { }),
            ["garbage"] = "not.a.token",
            ["too long"] = new string('a', MaxTokenLength + 1),
        };

        Assert.Equal(HttpStatusCode.OK, (await GetAsync(sample, "/api/me", Sign(Real(real), SecurityAlgorithms.EcdsaSha256, d => { }))).StatusCode);
        foreach ((string name, string token) in refused)
        {
            HttpResponseMessage response = await GetAsync(sample, "/api/me", token);
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, name + " answered " + response.StatusCode);
            Assert.True(response.Headers.WwwAuthenticate.ToString() == "Bearer error=\"invalid_token\"", name + ": " + response.Headers.WwwAuthenticate);
            Assert.Equal(0, response.Content.Headers.ContentLength ?? 0);
        }
    }

    [Fact]
    public async Task A_token_signed_with_a_rotated_key_is_accepted_after_one_rate_limited_refresh()
    {
        string kid = "rot-" + Guid.NewGuid().ToString("N")[..8];
        using ECDsa next = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        WebApplicationFactory<Program> central = api.Factory.WithWebHostBuilder(builder =>
        {
            Dictionary<string, string?> settings = new() { ["Secrets:" + kid] = next.ExportPkcs8PrivateKeyPem() };
            builder.UseSetting("Secrets:" + kid, settings["Secrets:" + kid]);
            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
            builder.ConfigureTestServices(services => services.AddSingleton<IClock>(clock));
        });
        hosts.Add(central);
        JwksSource jwks = new(central.Server.CreateHandler());

        // A long refresh interval: only the unknown-kid refresh can pick the new key up.
        HttpClient sample = Sample(jwks, o => (o.JwksRefreshInterval, o.JwksMaxStaleness) = (TimeSpan.FromHours(1), TimeSpan.FromHours(2)));
        try
        {
            Assert.Equal(HttpStatusCode.OK, (await GetAsync(sample, "/api/me", await MintAsync(central, AppAudience, ClientId, []))).StatusCode);
            Assert.Equal(1, jwks.Fetches);

            await using (AsyncServiceScope scope = central.Services.CreateAsyncScope())
            {
                await scope.ServiceProvider.GetRequiredService<ISigningKeyRotation>()
                    .AddKeyAsync(kid, SigningKeyAlgorithm.ES256, kid, clock.UtcNow.AddMinutes(16), CancellationToken.None);
            }

            clock.Shift(TimeSpan.FromMinutes(17));
            string rotated = await MintAsync(central, AppAudience, ClientId, []);
            Assert.Equal(kid, new JsonWebToken(rotated).Kid);

            HttpResponseMessage accepted = await GetAsync(sample, "/api/me", rotated);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            Assert.Equal(2, jwks.Fetches);

            // A flood of unknown kids right after: no fetch per request (at most one per JwksMinRefreshInterval).
            using ECDsa stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            for (int i = 0; i < 5; i++)
            {
                string unknown = Sign(new ECDsaSecurityKey(stranger) { KeyId = "unknown-" + i }, SecurityAlgorithms.EcdsaSha256, d => { }, clock.UtcNow);
                Assert.Equal(HttpStatusCode.Unauthorized, (await GetAsync(sample, "/api/me", unknown)).StatusCode);
            }

            Assert.Equal(2, jwks.Fetches);
            Assert.Equal(HttpStatusCode.OK, (await GetAsync(sample, "/api/me", rotated)).StatusCode);
        }
        finally
        {
            await using AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().SigningKey.Where(k => k.Kid == kid).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task With_the_JWKS_unreachable_at_first_use_every_token_is_refused_until_it_loads()
    {
        JwksSource jwks = new(api.Factory.Server.CreateHandler()) { Down = true };
        HttpClient sample = Sample(jwks);
        string token = await MintAsync(api.Factory, AppAudience, ClientId, []);

        HttpResponseMessage down = await GetAsync(sample, "/api/me", token);
        HttpResponseMessage stillRateLimited = await GetAsync(sample, "/api/me", token);
        jwks.Down = false;
        HttpResponseMessage beforeRetryWindow = await GetAsync(sample, "/api/me", token);
        int fetchesWhileRateLimited = jwks.Fetches;
        clock.Shift(TimeSpan.FromSeconds(31));
        HttpResponseMessage recovered = await GetAsync(sample, "/api/me", await MintAsync(api.Factory, AppAudience, ClientId, []));

        Assert.Equal(HttpStatusCode.Unauthorized, down.StatusCode);
        Assert.Equal("Bearer error=\"invalid_token\"", down.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, stillRateLimited.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, beforeRetryWindow.StatusCode);
        Assert.Equal(1, fetchesWhileRateLimited);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(2, jwks.Fetches);
    }

    [Fact]
    public async Task Cookie_mode_reads_the_shared_domain_cookie_with_an_XSRF_double_submit_and_the_Bearer_header_wins()
    {
        HttpClient sample = Sample(new JwksSource(api.Factory.Server.CreateHandler()), o =>
        {
            (o.Audience, o.ClientId, o.AcceptCookie) = (ApiFixture.Issuer, null, true);
        });
        string browser = await MintAsync(api.Factory, ApiFixture.Issuer, null, []);
        string app = await MintAsync(api.Factory, AppAudience, ClientId, []);

        HttpResponseMessage me = await SendAsync(sample, HttpMethod.Get, "/api/me", cookie: browser);
        HttpResponseMessage postWithoutXsrf = await SendAsync(sample, HttpMethod.Post, "/api/notes", cookie: browser);
        HttpResponseMessage postWrongXsrf = await SendAsync(sample, HttpMethod.Post, "/api/notes", cookie: browser, xsrf: ("a", "b"));
        HttpResponseMessage postWithXsrf = await SendAsync(sample, HttpMethod.Post, "/api/notes", cookie: browser, xsrf: ("same", "same"));
        HttpResponseMessage bearerWins = await SendAsync(sample, HttpMethod.Get, "/api/me", cookie: browser, bearer: "not.a.token");
        HttpResponseMessage appTokenInCookie = await SendAsync(sample, HttpMethod.Get, "/api/me", cookie: app);
        HttpResponseMessage browserBearer = await SendAsync(sample, HttpMethod.Get, "/api/me", bearer: browser);

        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, postWithoutXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, postWrongXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, postWithXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, bearerWins.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, appTokenInCookie.StatusCode);
        Assert.Equal(HttpStatusCode.OK, browserBearer.StatusCode);
    }

    [Fact]
    public async Task The_optional_session_hook_can_end_a_valid_token_and_fails_closed()
    {
        SessionHook hook = new();
        HttpClient sample = Sample(new JwksSource(api.Factory.Server.CreateHandler()), services: s => s.AddSingleton<ICentralAuthSessionValidator>(hook));
        Guid session = Guid.NewGuid();
        string token = await MintAsync(api.Factory, AppAudience, ClientId, [], session: session);

        HttpResponseMessage live = await GetAsync(sample, "/api/me", token);
        hook.Answer = false;
        HttpResponseMessage ended = await GetAsync(sample, "/api/me", token);
        hook.Answer = null;
        HttpResponseMessage broken = await GetAsync(sample, "/api/me", token);

        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal((ApiFixture.UserId, (Guid?)session), hook.Seen);
        Assert.Equal(HttpStatusCode.Unauthorized, ended.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, broken.StatusCode);
    }

    [Fact]
    public void A_misconfigured_sample_does_not_start()
    {
        WebApplicationFactory<SampleApiProgram> broken = new WebApplicationFactory<SampleApiProgram>().WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.Configure<CentralAuthOptions>(CentralAuthDefaults.AuthenticationScheme, o =>
                (o.JwksUri, o.AcceptCookie) = (new Uri("http://auth.example.test/.well-known/jwks.json"), true))));
        hosts.Add(broken);

        Exception error = Assert.ThrowsAny<Exception>(() => broken.CreateClient());
        Assert.Contains("https", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("AcceptCookie needs ClientId null", error.ToString(), StringComparison.Ordinal);
    }

    /// <summary>Auth.Client refuses tokens longer than this (CentralAuthHandler.MaxTokenLength).</summary>
    private const int MaxTokenLength = 8192;

    private static ECDsaSecurityKey Real(ECDsa key) => new ECDsaSecurityKey(key) { KeyId = ApiFixture.SigningKid };

    /// <summary>A token like central auth's app token, signed with <paramref name="key"/>, then changed by <paramref name="change"/>.</summary>
    private static string Sign(SecurityKey key, string algorithm, Action<SecurityTokenDescriptor> change, DateTime? at = null)
    {
        DateTime now = at ?? DateTime.UtcNow;
        SecurityTokenDescriptor descriptor = new()
        {
            Issuer = ApiFixture.Issuer,
            Audience = AppAudience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(15),
            TokenType = "at+jwt",
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [AuthClaimTypes.Subject] = ApiFixture.UserId.ToString(),
                [AuthClaimTypes.Name] = "Sample User",
                [AuthClaimTypes.ClientId] = ClientId,
            },
            SigningCredentials = new SigningCredentials(key, algorithm),
        };
        change(descriptor);
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    private static string Unsigned()
    {
        static string Part(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
        long exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds();
        return Part("{\"alg\":\"none\",\"typ\":\"at+jwt\",\"kid\":\"" + ApiFixture.SigningKid + "\"}") + "."
            + Part("{\"iss\":\"" + ApiFixture.Issuer + "\",\"aud\":\"" + AppAudience + "\",\"sub\":\"" + ApiFixture.UserId + "\",\"client_id\":\"" + ClientId + "\",\"exp\":" + exp + "}") + ".";
    }

    private static async Task<string> MintAsync(WebApplicationFactory<Program> central, string audience, string? clientId, IReadOnlyCollection<string> roles, Guid? session = null)
    {
        await using AsyncServiceScope scope = central.Services.CreateAsyncScope();
        AccessToken token = await scope.ServiceProvider.GetRequiredService<ITokenService>().CreateAccessTokenAsync(
            new AccessTokenRequest(ApiFixture.UserId, "user@example.test", "Sample User", roles, [], audience, clientId, session ?? Guid.NewGuid()),
            CancellationToken.None);
        return token.Jwt;
    }

    private static Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string token) =>
        SendAsync(client, HttpMethod.Get, path, bearer: token);

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string path, string? bearer = null, string? cookie = null, (string Header, string Cookie)? xsrf = null)
    {
        HttpRequestMessage request = new(method, path);
        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        List<string> cookies = [];
        if (cookie is not null)
        {
            cookies.Add(AuthCookieNames.AccessWithDomain + "=" + cookie);
        }

        if (xsrf is (string header, string value))
        {
            cookies.Add(AuthCookieNames.Xsrf + "=" + value);
            request.Headers.Add(AuthCookieNames.XsrfHeader, header);
        }

        if (cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", cookies));
        }

        return client.SendAsync(request);
    }

    /// <summary>The sample API, its JWKS fetched through <paramref name="jwks"/>, on the shared test clock.</summary>
    private HttpClient Sample(JwksSource jwks, Action<CentralAuthOptions>? options = null, Action<IServiceCollection>? services = null)
    {
        WebApplicationFactory<SampleApiProgram> factory = new WebApplicationFactory<SampleApiProgram>().WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(s =>
            {
                s.Configure<CentralAuthOptions>(CentralAuthDefaults.AuthenticationScheme, o =>
                {
                    (o.Issuer, o.Audience, o.ClientId, o.JwksUri) = (ApiFixture.Issuer, AppAudience, ClientId, null);
                    options?.Invoke(o);
                });
                s.AddHttpClient(CentralAuthDefaults.JwksHttpClientName).ConfigurePrimaryHttpMessageHandler(() => jwks);
                s.AddSingleton<TimeProvider>(clock);
                services?.Invoke(s);
            }));
        hosts.Add(factory);
        return factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://sample.example.test") });
    }

    /// <summary>Forwards JWKS fetches to a central-auth TestServer, counting them; can play "unreachable".</summary>
    private sealed class JwksSource(HttpMessageHandler central) : DelegatingHandler(central)
    {
        private int fetches;

        public bool Down { get; set; }

        public int Fetches => Volatile.Read(ref fetches);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref fetches);
            return Down ? throw new HttpRequestException("central auth unreachable") : base.SendAsync(request, cancellationToken);
        }
    }

    private sealed class SessionHook : ICentralAuthSessionValidator
    {
        public bool? Answer { get; set; } = true;

        public (Guid UserId, Guid? SessionId) Seen { get; private set; }

        public Task<bool> IsLiveAsync(Guid userId, Guid? sessionId, ClaimsPrincipal principal, CancellationToken cancellationToken)
        {
            Seen = (userId, sessionId);
            return Answer is bool answer ? Task.FromResult(answer) : throw new InvalidOperationException("session store down");
        }
    }

    /// <summary>One clock for central auth (IClock) and the sample (TimeProvider), shiftable together.</summary>
    private sealed class SharedClock : TimeProvider, IClock
    {
        private long offsetTicks;

        public DateTime UtcNow => DateTime.UtcNow.AddTicks(Interlocked.Read(ref offsetTicks));

        public override DateTimeOffset GetUtcNow() => new(UtcNow, TimeSpan.Zero);

        public void Shift(TimeSpan by) => Interlocked.Add(ref offsetTicks, by.Ticks);
    }
}
