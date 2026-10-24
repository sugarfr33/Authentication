using System.Buffers.Text;
using System.Diagnostics.Tracing;
using System.Security.Cryptography;
using Auth.Contracts;
using Auth.Contracts.Responses;
using Auth.Entities;
using Auth.Services.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Auth.UnitTests.Tokens;

/// <summary>
/// Access tokens: shape and claims, and one rejection test per attack. IdentityModel checks lifetime against the
/// system clock, so these tests start the fake clock at the real current time.
/// </summary>
public sealed class TokenServiceTests : IDisposable
{
    private const string Issuer = "https://auth.example.test";
    private const string Audience = "api://orders";
    private static readonly CancellationToken Ct = CancellationToken.None;
    private static readonly DateTime RealNow = TruncateToSeconds(DateTime.UtcNow);

    private readonly KeyHarness harness = new(new TokenOptions { Issuer = Issuer }, RealNow);
    private readonly JsonWebTokenHandler handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly TokenService service;

    public TokenServiceTests()
    {
        service = new TokenService(harness.Provider, harness.Clock, harness.Options);
    }

    private static AccessTokenRequest Request => new(
        Guid.Parse("7d0f6a2e-1b3c-4d5e-8f90-a1b2c3d4e5f6"),
        "ada@example.test",
        "Ada",
        ["Admin", "User"],
        ["users.read", "apps.manage"],
        Audience,
        "orders-spa",
        Guid.Parse("11111111-2222-3333-4444-555555555555"));

    [Fact]
    public async Task Token_is_an_ES256_at_jwt_with_kid_and_15_minute_lifetime_and_all_claims()
    {
        string pem = await harness.AddKeyAsync("k1", RealNow);
        AccessToken token = await service.CreateAccessTokenAsync(Request, Ct);
        JsonWebToken jwt = new(token.Jwt);

        Assert.Equal("ES256", jwt.Alg);
        Assert.Equal("k1", jwt.Kid);
        Assert.Equal("at+jwt", jwt.Typ);
        Assert.Equal(RealNow.AddMinutes(15), token.ExpiresUtc);
        Assert.Equal(TimeSpan.FromMinutes(15), jwt.ValidTo - jwt.IssuedAt);
        Assert.Equal(Issuer, jwt.Issuer);
        Assert.Equal([Audience], jwt.Audiences);
        Assert.Equal(Request.UserId.ToString(), jwt.Subject);
        Assert.Equal("ada@example.test", jwt.GetClaim(AuthClaimTypes.Email).Value);
        Assert.Equal("Ada", jwt.GetClaim(AuthClaimTypes.Name).Value);
        Assert.Equal(["Admin", "User"], jwt.Claims.Where(c => c.Type == AuthClaimTypes.Role).Select(c => c.Value));
        Assert.Equal(["users.read", "apps.manage"], jwt.Claims.Where(c => c.Type == AuthClaimTypes.Permission).Select(c => c.Value));
        Assert.Equal("orders-spa", jwt.GetClaim(AuthClaimTypes.ClientId).Value);
        Assert.Equal(Request.SessionId.ToString(), jwt.GetClaim(AuthClaimTypes.SessionId).Value);
        Assert.False(string.IsNullOrEmpty(jwt.Id));
        Assert.DoesNotContain(PrivateScalar(pem), token.Jwt, StringComparison.Ordinal);

        TokenValidationResult result = await service.ValidateAsync(token.Jwt, Audience, Ct);
        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task RS256_keys_are_supported()
    {
        await harness.AddKeyAsync("r1", RealNow, SigningKeyAlgorithm.RS256);
        AccessToken token = await service.CreateAccessTokenAsync(Request, Ct);

        Assert.Equal("RS256", new JsonWebToken(token.Jwt).Alg);
        Assert.True((await service.ValidateAsync(token.Jwt, Audience, Ct)).IsValid);
    }

    [Fact]
    public async Task Validation_parameters_pin_issuer_audience_lifetime_type_and_the_active_algorithm()
    {
        await harness.AddKeyAsync("k1", RealNow);

        TokenValidationParameters parameters = await service.GetValidationParametersAsync(null, Ct);

        Assert.True(parameters.ValidateIssuer && parameters.ValidateAudience && parameters.ValidateLifetime);
        Assert.True(parameters.RequireSignedTokens && parameters.RequireExpirationTime && parameters.ValidateIssuerSigningKey);
        Assert.Equal(Issuer, parameters.ValidIssuer);
        Assert.Equal(Issuer, parameters.ValidAudience);
        Assert.Equal(["ES256"], parameters.ValidAlgorithms);
        Assert.Equal(["at+jwt"], parameters.ValidTypes);
        Assert.False(parameters.TryAllIssuerSigningKeys);
        Assert.True(parameters.ClockSkew <= TimeSpan.FromSeconds(30));
        Assert.False(IdentityModelEventSource.ShowPII);
    }

    [Fact]
    public async Task Unsigned_alg_none_token_is_rejected()
    {
        await harness.AddKeyAsync("k1", RealNow);
        string unsigned = handler.CreateToken(Descriptor(signingCredentials: null));

        Assert.Equal("none", new JsonWebToken(unsigned).Alg);
        await AssertRejectedAsync(unsigned);
    }

    [Fact]
    public async Task HS256_token_signed_with_the_public_key_is_rejected()
    {
        await harness.AddKeyAsync("k1", RealNow);
        JsonWebKeyDto jwk = Assert.Single((await harness.Provider.GetJwksAsync(Ct)).Keys);
        byte[] publicPoint = [.. Base64Url.DecodeFromChars(jwk.X!), .. Base64Url.DecodeFromChars(jwk.Y!)];
        byte[] spki = ((ECDsa)(await harness.Provider.GetValidationKeysAsync(Ct))[0].PublicKey).ExportSubjectPublicKeyInfo();

        foreach (byte[] secret in new[] { publicPoint, spki, [.. publicPoint, .. publicPoint] })
        {
            SigningCredentials hmac = new(new SymmetricSecurityKey(secret) { KeyId = "k1" }, SecurityAlgorithms.HmacSha256);
            await AssertRejectedAsync(handler.CreateToken(Descriptor(hmac)));
        }
    }

    [Fact]
    public async Task Token_with_an_unknown_kid_is_rejected()
    {
        string pem = await harness.AddKeyAsync("k1", RealNow);
        using ECDsa realKey = ECDsa.Create();
        realKey.ImportFromPem(pem);

        await AssertRejectedAsync(handler.CreateToken(Descriptor(Es256(realKey, "not-published"))));
    }

    [Fact]
    public async Task Token_signed_with_another_key_under_a_published_kid_is_rejected()
    {
        await harness.AddKeyAsync("k1", RealNow);
        using ECDsa attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await AssertRejectedAsync(handler.CreateToken(Descriptor(Es256(attacker, "k1"))));
    }

    [Fact]
    public async Task Token_whose_alg_differs_from_the_key_algorithm_is_rejected()
    {
        await harness.AddKeyAsync("k1", RealNow);
        using RSA rsa = RSA.Create(2048);
        SigningCredentials rs256UnderEcKid = new(new RsaSecurityKey(rsa) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256);

        await AssertRejectedAsync(handler.CreateToken(Descriptor(rs256UnderEcKid)));
    }

    [Fact]
    public async Task Expired_token_is_rejected_and_skew_is_at_most_30_seconds()
    {
        harness.Clock.Set(RealNow - TimeSpan.FromHours(2));
        await harness.AddKeyAsync("k1", harness.Clock.UtcNow);

        harness.Clock.Set(RealNow - TimeSpan.FromMinutes(15) - TimeSpan.FromSeconds(10));
        string withinSkew = (await service.CreateAccessTokenAsync(Request, Ct)).Jwt;
        harness.Clock.Set(RealNow - TimeSpan.FromMinutes(15) - TimeSpan.FromSeconds(90));
        string beyondSkew = (await service.CreateAccessTokenAsync(Request, Ct)).Jwt;
        harness.Clock.Set(RealNow - TimeSpan.FromHours(1));
        string longExpired = (await service.CreateAccessTokenAsync(Request, Ct)).Jwt;
        harness.Clock.Set(RealNow);

        Assert.True((await service.ValidateAsync(withinSkew, Audience, Ct)).IsValid);
        await AssertRejectedAsync(beyondSkew);
        TokenValidationResult result = await AssertRejectedAsync(longExpired);
        Assert.IsType<SecurityTokenExpiredException>(result.Exception);
    }

    [Fact]
    public async Task Token_from_another_issuer_is_rejected()
    {
        await harness.AddKeyAsync("k1", RealNow);
        TokenService otherIssuer = new(harness.Provider, harness.Clock, new TokenOptions { Issuer = "https://evil.example.test" }.Validated());

        TokenValidationResult result = await AssertRejectedAsync((await otherIssuer.CreateAccessTokenAsync(Request, Ct)).Jwt);
        Assert.IsType<SecurityTokenInvalidIssuerException>(result.Exception);
    }

    [Fact]
    public async Task Token_for_another_audience_is_rejected()
    {
        await harness.AddKeyAsync("k1", RealNow);
        AccessToken token = await service.CreateAccessTokenAsync(Request, Ct);

        TokenValidationResult result = await service.ValidateAsync(token.Jwt, "api://payroll", Ct);

        Assert.False(result.IsValid);
        Assert.IsType<SecurityTokenInvalidAudienceException>(result.Exception);
    }

    [Fact]
    public async Task Correctly_signed_JWT_of_another_type_is_rejected()
    {
        string pem = await harness.AddKeyAsync("k1", RealNow);
        using ECDsa realKey = ECDsa.Create();
        realKey.ImportFromPem(pem);
        SecurityTokenDescriptor idToken = Descriptor(Es256(realKey, "k1"));
        idToken.TokenType = "JWT";

        await AssertRejectedAsync(handler.CreateToken(idToken));
    }

    [Fact]
    public async Task No_private_key_material_in_IdentityModel_logs_or_validation_errors()
    {
        string pem = await harness.AddKeyAsync("k1", RealNow);
        using IdentityModelListener listener = new();
        using ECDsa attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        List<string> texts = [];

        AccessToken token = await service.CreateAccessTokenAsync(Request, Ct);
        texts.Add(token.Jwt);
        foreach (string bad in new[]
        {
            handler.CreateToken(Descriptor(Es256(attacker, "k1"))),
            handler.CreateToken(Descriptor(signingCredentials: null)),
            token.Jwt + "x",
        })
        {
            TokenValidationResult result = await service.ValidateAsync(bad, Audience, Ct);
            Assert.False(result.IsValid);
            texts.Add(result.Exception?.ToString() ?? string.Empty);
        }

        texts.AddRange(listener.Messages);
        string scalar = PrivateScalar(pem);
        string pemBody = string.Concat(pem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)).Select(l => l.Trim()));
        Assert.All(texts, t => Assert.DoesNotContain(scalar, t, StringComparison.Ordinal));
        Assert.All(texts, t => Assert.DoesNotContain(pemBody, t, StringComparison.Ordinal));
    }

    public void Dispose() => harness.Dispose();

    private async Task<TokenValidationResult> AssertRejectedAsync(string jwt)
    {
        TokenValidationResult result = await service.ValidateAsync(jwt, Audience, Ct);
        Assert.False(result.IsValid);
        Assert.NotNull(result.Exception);
        return result;
    }

    private SecurityTokenDescriptor Descriptor(SigningCredentials? signingCredentials) => new()
    {
        Issuer = Issuer,
        Audience = Audience,
        IssuedAt = harness.Clock.UtcNow,
        NotBefore = harness.Clock.UtcNow,
        Expires = harness.Clock.UtcNow.AddMinutes(15),
        TokenType = "at+jwt",
        Claims = new Dictionary<string, object> { [AuthClaimTypes.Subject] = Guid.NewGuid().ToString(), [AuthClaimTypes.Role] = new[] { "Admin" } },
        SigningCredentials = signingCredentials,
    };

    private static SigningCredentials Es256(ECDsa key, string kid) =>
        new(new ECDsaSecurityKey(key) { KeyId = kid }, SecurityAlgorithms.EcdsaSha256);

    private static string PrivateScalar(string pem)
    {
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(pem);
        return Base64Url.EncodeToString(key.ExportParameters(includePrivateParameters: true).D);
    }

    private static DateTime TruncateToSeconds(DateTime utc) => new(utc.Ticks - (utc.Ticks % TimeSpan.TicksPerSecond), DateTimeKind.Utc);

    /// <summary>Captures every IdentityModel EventSource message at Verbose.</summary>
    private sealed class IdentityModelListener : EventListener
    {
        private readonly List<string> messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (messages)
                {
                    return [.. messages];
                }
            }
        }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name.Contains("IdentityModel", StringComparison.OrdinalIgnoreCase))
            {
                EnableEvents(eventSource, EventLevel.Verbose);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            lock (messages)
            {
                messages.Add(eventData.Message + " " + string.Join(" ", eventData.Payload ?? []));
            }
        }
    }
}
