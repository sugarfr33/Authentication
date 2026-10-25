using System.Net;
using System.Security.Cryptography;
using System.Text;
using Auth.Client;
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
        Assert.True((await f.Cache.GetKeysAsync("k1", CancellationToken.None)).Contains("k1"));
        Assert.Equal(2, f.Endpoint.Fetches);

        f.Time.Advance(TimeSpan.FromMinutes(55));
        await Assert.ThrowsAsync<JwksUnavailableException>(() => f.Cache.GetKeysAsync("k1", CancellationToken.None));
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
    public void Options_are_validated(string issuer, string audience, string? clientId, string jwks, bool bearer, bool cookie, string expected)
    {
        CentralAuthOptions options = new() { Issuer = issuer, Audience = audience, ClientId = clientId, JwksUri = new Uri(jwks), AcceptBearer = bearer, AcceptCookie = cookie };

        ValidateOptionsResult result = new CentralAuthOptionsValidator().Validate("CentralAuth", options);

        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage, StringComparison.Ordinal);
    }

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
            Cache = new JwksCache(options, new Clients(Endpoint), Time, NullLogger.Instance);
        }

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

        public int Fetches => Volatile.Read(ref fetches);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref fetches);
            await Task.Delay(Delay, cancellationToken);
            return Down
                ? throw new HttpRequestException("down")
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body, Encoding.UTF8, "application/jwk-set+json") };
        }
    }

    private sealed class Clients(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class FakeTime : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 25, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now += by;
    }
}
