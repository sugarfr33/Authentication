using System.Net;
using System.Security.Cryptography;
using System.Text;
using Auth.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.UnitTests.Client;

/// <summary>T22: the client's JWKS cache (docs/t22-client-extension.md section 5) with a fake JWKS endpoint and clock.</summary>
public class JwksCacheTests
{
    [Fact]
    public async Task Concurrent_first_uses_share_one_fetch_and_later_calls_use_the_cache()
    {
        Fixture f = new(Jwks(Ec("k1")));
        f.Endpoint.Delay = TimeSpan.FromMilliseconds(100);

        JwksKeys[] all = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => f.Cache.GetKeysAsync("k1", CancellationToken.None)));
        f.Time.Advance(TimeSpan.FromMinutes(4));
        await f.Cache.GetKeysAsync("k1", CancellationToken.None);

        Assert.All(all, k => Assert.True(k.Contains("k1")));
        Assert.Equal(1, f.Endpoint.Fetches);
    }

    [Fact]
    public async Task An_unknown_kid_refreshes_at_most_once_per_minimum_interval()
    {
        Fixture f = new(Jwks(Ec("k1")));
        await f.Cache.GetKeysAsync("k1", CancellationToken.None);
        f.Endpoint.Body = Jwks(Ec("k1"), Ec("k2"));

        f.Time.Advance(TimeSpan.FromSeconds(31));
        Assert.True((await f.Cache.GetKeysAsync("k2", CancellationToken.None)).Contains("k2"));
        for (int i = 0; i < 5; i++)
        {
            Assert.False((await f.Cache.GetKeysAsync("unknown-" + i, CancellationToken.None)).Contains("unknown-" + i));
        }

        Assert.Equal(2, f.Endpoint.Fetches);
        f.Time.Advance(TimeSpan.FromSeconds(31));
        await f.Cache.GetKeysAsync("unknown-again", CancellationToken.None);
        Assert.Equal(3, f.Endpoint.Fetches);
    }

    [Fact]
    public async Task A_failed_first_fetch_fails_closed_and_is_retried_only_after_the_minimum_interval()
    {
        Fixture f = new(Jwks(Ec("k1"))) { };
        f.Endpoint.Down = true;

        await Assert.ThrowsAsync<JwksUnavailableException>(() => f.Cache.GetKeysAsync("k1", CancellationToken.None));
        f.Endpoint.Down = false;
        await Assert.ThrowsAsync<JwksUnavailableException>(() => f.Cache.GetKeysAsync("k1", CancellationToken.None));
        Assert.Equal(1, f.Endpoint.Fetches);

        f.Time.Advance(TimeSpan.FromSeconds(31));
        Assert.True((await f.Cache.GetKeysAsync("k1", CancellationToken.None)).Contains("k1"));
        Assert.Equal(2, f.Endpoint.Fetches);
    }

    [Fact]
    public async Task When_refreshes_fail_the_last_good_keys_serve_until_the_maximum_staleness()
    {
        Fixture f = new(Jwks(Ec("k1")));
        await f.Cache.GetKeysAsync("k1", CancellationToken.None);
        f.Endpoint.Down = true;

        f.Time.Advance(TimeSpan.FromMinutes(6));
        Assert.True((await f.Cache.GetKeysAsync("k1", CancellationToken.None)).Contains("k1"));
        await f.Cache.BackgroundRefresh!;
        Assert.True((await f.Cache.GetKeysAsync("k1", CancellationToken.None)).Contains("k1"));
        Assert.Equal(2, f.Endpoint.Fetches);
        Assert.Contains(f.Logs.Messages, m => m.StartsWith("Serving stale central-auth signing keys (6 min old)", StringComparison.Ordinal));

        f.Time.Advance(TimeSpan.FromMinutes(55));
        await Assert.ThrowsAsync<JwksUnavailableException>(() => f.Cache.GetKeysAsync("k1", CancellationToken.None));
    }

    [Fact]
    public async Task Stale_keys_are_served_at_once_while_one_background_refresh_runs()
    {
        Fixture f = new(Jwks(Ec("k1")));
        await f.Cache.GetKeysAsync("k1", CancellationToken.None);
        f.Endpoint.Body = Jwks(Ec("k1"), Ec("k2"));
        f.Endpoint.Hold = new TaskCompletionSource();
        f.Time.Advance(TimeSpan.FromMinutes(6));

        // The endpoint is blocked: callers must not queue behind it.
        Task<JwksKeys[]> callers = Task.WhenAll(Enumerable.Range(0, 5).Select(_ => f.Cache.GetKeysAsync("k1", CancellationToken.None)));
        JwksKeys[] served = await callers.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.All(served, k => Assert.False(k.Contains("k2")));

        f.Endpoint.Hold.SetResult();
        await f.Cache.BackgroundRefresh!;
        Assert.True((await f.Cache.GetKeysAsync("k2", CancellationToken.None)).Contains("k2"));
        Assert.Equal(2, f.Endpoint.Fetches);
    }

    [Fact]
    public async Task A_redirect_or_any_unexpected_fetch_error_is_a_failed_fetch_never_an_escaping_exception()
    {
        Fixture redirect = new(Jwks(Ec("k1")));
        redirect.Endpoint.Status = HttpStatusCode.Found;
        Fixture odd = new(Jwks(Ec("k1")));
        odd.Endpoint.Throw = new InvalidOperationException("odd");

        await Assert.ThrowsAsync<JwksUnavailableException>(() => redirect.Cache.GetKeysAsync("k1", CancellationToken.None));
        await Assert.ThrowsAsync<JwksUnavailableException>(() => odd.Cache.GetKeysAsync("k1", CancellationToken.None));
    }

    [Fact]
    public void The_JWKS_client_never_follows_redirects()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddCentralAuth(o => (o.Issuer, o.Audience) = ("https://auth.example.test", "api://x"));
        using ServiceProvider provider = services.BuildServiceProvider();

        HttpMessageHandler? handler = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(CentralAuthDefaults.JwksHttpClientName);
        while (handler is DelegatingHandler delegating)
        {
            handler = delegating.InnerHandler;
        }

        Assert.False(Assert.IsType<SocketsHttpHandler>(handler).AllowAutoRedirect);
    }

    [Fact]
    public void Only_public_signing_keys_of_the_two_central_auth_algorithms_are_kept()
    {
        using RSA small = RSA.Create(1024);
        using RSA rsa = RSA.Create(2048);
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        string json = Jwks(
            Ec("good-ec"),
            Rsa("good-rsa", rsa),
            Rsa("small-rsa", small),
            Ec("enc", use: "enc"),
            Ec("hs", alg: "HS256"),
            Ec("private", withPrivate: true),
            "{\"kty\":\"EC\",\"use\":\"sig\",\"kid\":\"p384\",\"alg\":\"ES256\",\"crv\":\"P-384\",\"x\":\"" + B64(p384.ExportParameters(false).Q.X!) + "\",\"y\":\"" + B64(p384.ExportParameters(false).Q.Y!) + "\"}",
            Ec("good-ec"));

        JwksKeys keys = JwksCache.Parse(json);

        Assert.Equal(2, keys.Count);
        Assert.True(keys.Contains("good-ec") && keys.Contains("good-rsa"));
        Assert.Single(keys.Resolve("good-ec", SecurityAlgorithms.EcdsaSha256));
        Assert.Empty(keys.Resolve("good-ec", SecurityAlgorithms.RsaSha256));
        Assert.Empty(keys.Resolve("good-rsa", SecurityAlgorithms.EcdsaSha256));
        Assert.Throws<InvalidDataException>(() => JwksCache.Parse(Jwks(Ec("enc", use: "enc"))));
        Assert.Throws<InvalidDataException>(() => JwksCache.Parse(Jwks([.. Enumerable.Range(0, JwksCache.MaxKeys + 1).Select(i => Ec("k" + i))])));
        Assert.ThrowsAny<ArgumentException>(() => JwksCache.Parse("not json"));
    }

    /// <summary>
    /// Tester T22: the kid-plus-alg binding. End to end it is defence in depth (an EC key cannot verify RS256, and the
    /// parser drops mislabelled keys), so it is pinned here: a token alg that is not the key's own alg resolves nothing.
    /// </summary>
    [Fact]
    public void A_key_resolves_only_for_its_own_algorithm_in_both_directions()
    {
        using RSA rsa = RSA.Create(2048);
        JwksKeys keys = JwksCache.Parse(Jwks(Ec("ec-kid"), Rsa("rsa-kid", rsa)));

        Assert.Empty(keys.Resolve("ec-kid", SecurityAlgorithms.RsaSha256));
        Assert.Empty(keys.Resolve("rsa-kid", SecurityAlgorithms.EcdsaSha256));
        Assert.Empty(keys.Resolve("ec-kid", null));
        Assert.Empty(keys.Resolve("ec-kid", "none"));
        Assert.Empty(keys.Resolve(null, SecurityAlgorithms.EcdsaSha256));
        Assert.Single(keys.Resolve("ec-kid", SecurityAlgorithms.EcdsaSha256));
        Assert.Single(keys.Resolve("rsa-kid", SecurityAlgorithms.RsaSha256));
    }

    [Fact]
    public async Task An_oversized_JWKS_is_refused()
    {
        Fixture f = new("{\"keys\":[],\"pad\":\"" + new string('a', JwksCache.MaxDocumentBytes) + "\"}");

        await Assert.ThrowsAsync<JwksUnavailableException>(() => f.Cache.GetKeysAsync("k1", CancellationToken.None));
    }

    [Theory]
    [InlineData("", "api://x", null, "https://auth.example.test/.well-known/jwks.json", true, false, "Issuer")]
    [InlineData("https://auth.example.test", " ", null, "https://auth.example.test/.well-known/jwks.json", true, false, "Audience")]
    [InlineData("https://auth.example.test", "api://x", null, "http://auth.example.test/.well-known/jwks.json", true, false, "https")]
    [InlineData("https://auth.example.test", "api://x", "x", "https://auth.example.test/.well-known/jwks.json", true, true, "AcceptCookie needs ClientId null")]
    [InlineData("https://auth.example.test", "api://x", " ", "https://auth.example.test/.well-known/jwks.json", true, false, "ClientId")]
    [InlineData("https://auth.example.test", "api://x", null, "https://auth.example.test/.well-known/jwks.json", false, false, "accept the Bearer header")]
    [InlineData("https://auth.example.test", "api://x", null, "https://cdn.example.test/jwks.json", true, false, "issuer's host")]
    [InlineData("https://auth.example.test", "api://x", null, "https://user:pw@auth.example.test/jwks.json", true, false, "user information")]
    [InlineData("https://auth.example.test", "api://x", null, "ftp://auth.example.test/jwks.json", true, false, "must use https")]
    [InlineData("https://auth.example.test", "api://x", null, "https://auth.example.test/.well-known/jwks.json", true, true, "AllowedOrigins is required")]
    public void Options_are_validated(string issuer, string audience, string? clientId, string jwks, bool bearer, bool cookie, string expected)
    {
        CentralAuthOptions options = new() { Issuer = issuer, Audience = audience, ClientId = clientId, JwksUri = new Uri(jwks), AcceptBearer = bearer, AcceptCookie = cookie };

        ValidateOptionsResult result = new CentralAuthOptionsValidator().Validate("CentralAuth", options);

        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Cache_ages_are_capped_and_cookie_mode_needs_a_prefixed_cookie_and_plain_origins()
    {
        CentralAuthOptions tooOld = Valid();
        (tooOld.JwksRefreshInterval, tooOld.JwksMaxStaleness) = (TimeSpan.FromHours(25), TimeSpan.FromHours(26));
        CentralAuthOptions staleTooLong = Valid();
        staleTooLong.JwksMaxStaleness = TimeSpan.FromHours(25);
        CentralAuthOptions cookie = Valid();
        (cookie.ClientId, cookie.AcceptCookie, cookie.CookieName) = (null, true, "access");
        cookie.AllowedOrigins.Add("https://app.example.test/path");
        CentralAuthOptions foreign = Valid();
        (foreign.JwksUri, foreign.AllowForeignJwksHost) = (new Uri("https://cdn.example.test/jwks.json"), true);

        Assert.Contains("at most 24 hours", Validate(tooOld), StringComparison.Ordinal);
        Assert.Contains("between JwksRefreshInterval and 24 hours", Validate(staleTooLong), StringComparison.Ordinal);
        Assert.Contains("__Secure- or __Host-", Validate(cookie), StringComparison.Ordinal);
        Assert.Contains("AllowedOrigins entries must be origins", Validate(cookie), StringComparison.Ordinal);
        Assert.Null(Validate(foreign));
    }

    [Theory]
    [InlineData("https://App.Example.test", true, "https://app.example.test")]
    [InlineData("https://app.example.test:8443", true, "https://app.example.test:8443")]
    [InlineData("http://localhost:5173", false, "http://localhost:5173")]
    [InlineData("http://app.example.test", true, null)]
    [InlineData("https://app.example.test/x", true, null)]
    [InlineData("https://u@app.example.test", true, null)]
    [InlineData("null", true, null)]
    [InlineData("", true, null)]
    public void Origins_are_compared_in_normal_form(string value, bool requireHttps, string? expected) =>
        Assert.Equal(expected, OriginRules.Normalize(value, requireHttps));

    private static CentralAuthOptions Valid() => new()
    {
        Issuer = "https://auth.example.test",
        Audience = "api://x",
        ClientId = "x",
        JwksUri = new Uri("https://auth.example.test/.well-known/jwks.json"),
    };

    private static string? Validate(CentralAuthOptions options) => new CentralAuthOptionsValidator().Validate("CentralAuth", options) is { Failed: true } failed ? failed.FailureMessage : null;

    [Fact]
    public void Valid_options_pass_and_the_JWKS_URI_defaults_to_the_issuer()
    {
        CentralAuthOptions options = new() { Issuer = "https://auth.example.test/", Audience = "api://x", ClientId = "x" };
        new CentralAuthPostConfigure().PostConfigure("CentralAuth", options);

        Assert.Equal(new Uri("https://auth.example.test/.well-known/jwks.json"), options.JwksUri);
        Assert.True(new CentralAuthOptionsValidator().Validate("CentralAuth", options).Succeeded);
    }

    private static string B64(byte[] bytes) => Base64UrlEncoder.Encode(bytes);

    private static string Jwks(params string[] keys) => "{\"keys\":[" + string.Join(",", keys) + "]}";

    private static string Ec(string kid, string use = "sig", string alg = "ES256", bool withPrivate = false)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters p = key.ExportParameters(withPrivate);
        return "{\"kty\":\"EC\",\"use\":\"" + use + "\",\"kid\":\"" + kid + "\",\"alg\":\"" + alg + "\",\"crv\":\"P-256\",\"x\":\"" + B64(p.Q.X!) + "\",\"y\":\"" + B64(p.Q.Y!) + "\""
            + (withPrivate ? ",\"d\":\"" + B64(p.D!) + "\"" : string.Empty) + "}";
    }

    private static string Rsa(string kid, RSA key)
    {
        RSAParameters p = key.ExportParameters(false);
        return "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + kid + "\",\"alg\":\"RS256\",\"n\":\"" + B64(p.Modulus!) + "\",\"e\":\"" + B64(p.Exponent!) + "\"}";
    }

    private sealed class Fixture
    {
        public Fixture(string body)
        {
            Endpoint = new FakeEndpoint { Body = body };
            CentralAuthOptions options = new() { Issuer = "https://auth.example.test", Audience = "api://x", JwksUri = new Uri("https://auth.example.test/.well-known/jwks.json") };
            Cache = new JwksCache(options, new Clients(Endpoint), Time, Logs);
        }

        public CapturingLogger Logs { get; } = new();

        public FakeEndpoint Endpoint { get; }

        public FakeTime Time { get; } = new();

        public JwksCache Cache { get; }
    }

    private sealed class FakeEndpoint : HttpMessageHandler
    {
        private int fetches;

        public string Body { get; set; } = string.Empty;

        public bool Down { get; set; }

        public TimeSpan Delay { get; set; }

        public TaskCompletionSource? Hold { get; set; }

        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        public Exception? Throw { get; set; }

        public int Fetches => Volatile.Read(ref fetches);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref fetches);
            await Task.Delay(Delay, cancellationToken);
            if (Hold is TaskCompletionSource hold)
            {
                await hold.Task.WaitAsync(cancellationToken);
            }

            if (Throw is not null)
            {
                throw Throw;
            }

            return Down
                ? throw new HttpRequestException("down")
                : new HttpResponseMessage(Status) { Content = new StringContent(Body, Encoding.UTF8, "application/jwk-set+json") };
        }
    }

    private sealed class Clients(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Messages)
            {
                Messages.Add(formatter(state, exception));
            }
        }
    }

    private sealed class FakeTime : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 25, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now += by;
    }
}
