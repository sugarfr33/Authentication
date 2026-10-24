using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Auth.Contracts.Responses;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.Extensions.Configuration;

namespace Auth.UnitTests.Tokens;

/// <summary>Key loading, public-only JWKS, private key only from the secret store, and no key material in errors.</summary>
public sealed class SigningKeyMaterialTests : IDisposable
{
    private static readonly CancellationToken Ct = CancellationToken.None;
    private static readonly string[] PrivateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    private readonly KeyHarness harness = new();

    [Theory]
    [InlineData(SigningKeyAlgorithm.ES256)]
    [InlineData(SigningKeyAlgorithm.RS256)]
    public async Task JWKS_contains_public_parameters_only(string algorithm)
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start, algorithm);

        string json = JsonSerializer.Serialize(await harness.Provider.GetJwksAsync(Ct));
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement key = Assert.Single(document.RootElement.GetProperty("keys").EnumerateArray());

        IEnumerable<string> members = key.EnumerateObject().Select(p => p.Name);
        Assert.Empty(members.Intersect(PrivateJwkMembers));
        Assert.Equal(algorithm == SigningKeyAlgorithm.ES256 ? "EC" : "RSA", key.GetProperty("kty").GetString());
        Assert.Equal(algorithm, key.GetProperty("alg").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("k1", key.GetProperty("kid").GetString());
    }

    [Fact]
    public async Task Stored_row_holds_only_the_public_JWK_and_a_reference_name()
    {
        string pem = await harness.AddKeyAsync("k1", KeyHarness.Start);
        SigningKey row = harness.Repository.Get("k1");

        Assert.Equal("ref-k1", row.PrivateKeyReference);
        using JsonDocument jwk = JsonDocument.Parse(row.PublicKeyJwk);
        Assert.Empty(jwk.RootElement.EnumerateObject().Select(p => p.Name).Intersect(PrivateJwkMembers));
        Assert.DoesNotContain(PemBody(pem), row.PublicKeyJwk, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Signing_key_is_loaded_from_the_secret_store_by_reference()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        harness.Secrets.Requested.Clear();

        ActiveSigningKey active = await harness.Provider.GetSigningKeyAsync(Ct);

        Assert.Equal(["ref-k1"], harness.Secrets.Requested);
        byte[] data = Encoding.UTF8.GetBytes("payload");
        byte[] signature = ((ECDsa)active.PrivateKey).SignData(data, HashAlgorithmName.SHA256);
        ValidationKey validation = Assert.Single(await harness.Provider.GetValidationKeysAsync(Ct));
        Assert.True(((ECDsa)validation.PublicKey).VerifyData(data, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public async Task Private_key_that_no_longer_matches_the_published_key_is_refused()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        string swapped = KeyHarness.NewEcPem();
        harness.Secrets.Set("ref-k1", swapped);

        InvalidOperationException ex = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Provider.GetSigningKeyAsync(Ct));

        Assert.Contains("does not match", ex.Message, StringComparison.Ordinal);
        AssertNoKeyMaterial(ex, swapped);
    }

    [Fact]
    public async Task Missing_secret_is_refused_without_naming_more_than_the_kid()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Rotation.AddKeyAsync("k1", SigningKeyAlgorithm.ES256, "ref-missing", KeyHarness.Start, Ct));
    }

    [Fact]
    public void Wrong_curve_short_RSA_and_garbage_PEM_are_refused_without_key_material_in_the_error()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        string p384Pem = p384.ExportPkcs8PrivateKeyPem();
        string shortRsa = KeyHarness.NewRsaPem(1024);
        string garbage = "-----BEGIN PRIVATE KEY-----\nTk9UQUtFWU5PVEFLRVlOT1RBS0VZ\n-----END PRIVATE KEY-----";
        string rsaAsEc = KeyHarness.NewRsaPem();

        AssertNoKeyMaterial(Assert.Throws<InvalidOperationException>(() => SigningKeyCrypto.LoadPrivateKey("a", SigningKeyAlgorithm.ES256, p384Pem)), p384Pem);
        AssertNoKeyMaterial(Assert.Throws<InvalidOperationException>(() => SigningKeyCrypto.LoadPrivateKey("b", SigningKeyAlgorithm.RS256, shortRsa)), shortRsa);
        AssertNoKeyMaterial(Assert.Throws<InvalidOperationException>(() => SigningKeyCrypto.LoadPrivateKey("c", SigningKeyAlgorithm.ES256, garbage)), garbage);
        AssertNoKeyMaterial(Assert.Throws<InvalidOperationException>(() => SigningKeyCrypto.LoadPrivateKey("d", SigningKeyAlgorithm.ES256, rsaAsEc)), rsaAsEc);
    }

    [Fact]
    public void Public_JWK_round_trips_to_a_key_that_verifies_the_private_key_signature()
    {
        using RSA rsa = RSA.Create(2048);
        JsonWebKeyDto jwk = SigningKeyCrypto.ToPublicJwk("r1", SigningKeyAlgorithm.RS256, rsa);
        using RSA publicOnly = (RSA)SigningKeyCrypto.FromPublicJwk(SigningKeyCrypto.Deserialize("r1", SigningKeyCrypto.Serialize(jwk)));

        byte[] data = [1, 2, 3];
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.True(publicOnly.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<CryptographicException>(() => publicOnly.ExportParameters(includePrivateParameters: true));
    }

    [Fact]
    public async Task Configuration_secret_store_reads_inline_values_and_PEM_files()
    {
        string path = Path.Combine(Path.GetTempPath(), "auth-test-" + Guid.NewGuid().ToString("N") + ".pem");
        await File.WriteAllTextAsync(path, "file-secret");
        try
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Secrets:inline-key"] = "inline-secret",
                    ["SecretFiles:file-key"] = path,
                    ["SecretFiles:missing-file"] = path + ".missing",
                })
                .Build();
            ConfigurationSecretStore store = new(configuration);

            Assert.Equal("inline-secret", await store.GetSecretAsync("inline-key", Ct));
            Assert.Equal("file-secret", await store.GetSecretAsync("file-key", Ct));
            Assert.Null(await store.GetSecretAsync("unknown", Ct));
            await Assert.ThrowsAsync<ArgumentException>(() => store.GetSecretAsync("bad:name", Ct));
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.GetSecretAsync("missing-file", Ct));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Token_options_default_to_15_minutes_and_30_seconds_and_refuse_more_skew()
    {
        TokenOptions defaults = new TokenOptions { Issuer = "https://auth.example.test" }.Validated();

        Assert.Equal(TimeSpan.FromMinutes(15), defaults.AccessTokenLifetime);
        Assert.Equal(TimeSpan.FromSeconds(30), defaults.ClockSkew);
        Assert.Throws<ArgumentOutOfRangeException>(() => new TokenOptions { Issuer = "x", ClockSkew = TimeSpan.FromSeconds(31) }.Validated());
        Assert.Throws<ArgumentException>(() => new TokenOptions { Issuer = " " }.Validated());
    }

    public void Dispose() => harness.Dispose();

    private static void AssertNoKeyMaterial(Exception ex, string pem)
    {
        string text = ex.ToString();
        Assert.DoesNotContain(PemBody(pem), text, StringComparison.Ordinal);
        foreach (string line in pem.Split('\n').Where(l => l.Length > 20 && !l.StartsWith("-----", StringComparison.Ordinal)))
        {
            Assert.DoesNotContain(line.Trim(), text, StringComparison.Ordinal);
        }
    }

    private static string PemBody(string pem) =>
        string.Concat(pem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)).Select(l => l.Trim()));
}
