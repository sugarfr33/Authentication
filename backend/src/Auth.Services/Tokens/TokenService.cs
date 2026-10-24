using System.Security.Cryptography;
using Auth.Contracts;
using Auth.Entities;
using Auth.Services.Common;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Services.Tokens;

internal sealed class TokenService(SigningKeyProvider keys, IClock clock, TokenOptions options) : ITokenService
{
    /// <summary>RFC 9068 access-token type; validation accepts only this, so ID tokens or other JWTs cannot be replayed as access tokens.</summary>
    public const string AccessTokenType = "at+jwt";

    private readonly JsonWebTokenHandler handler = new() { MapInboundClaims = false, SetDefaultTimesOnTokenCreation = false };

    public async Task<AccessToken> CreateAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Audience, nameof(request));

        ActiveSigningKey key = await keys.GetSigningKeyAsync(cancellationToken);
        DateTime now = clock.UtcNow;
        DateTime expires = now + options.AccessTokenLifetime;

        Dictionary<string, object> claims = new(StringComparer.Ordinal)
        {
            [AuthClaimTypes.Subject] = request.UserId.ToString(),
            [AuthClaimTypes.Email] = request.Email,
            [AuthClaimTypes.Name] = request.DisplayName,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
        };
        AddIfAny(claims, AuthClaimTypes.Role, request.Roles);
        AddIfAny(claims, AuthClaimTypes.Permission, request.Permissions);
        if (request.ClientId is not null)
        {
            claims[AuthClaimTypes.ClientId] = request.ClientId;
        }

        if (request.SessionId is not null)
        {
            claims[AuthClaimTypes.SessionId] = request.SessionId.Value.ToString();
        }

        SecurityTokenDescriptor descriptor = new()
        {
            Issuer = options.Issuer,
            Audience = request.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            TokenType = AccessTokenType,
            Claims = claims,
            SigningCredentials = new SigningCredentials(ToSecurityKey(key.Kid, key.PrivateKey), ToSecurityAlgorithm(key.Algorithm)),
        };

        return new AccessToken(handler.CreateToken(descriptor), expires);
    }

    public async Task<TokenValidationParameters> GetValidationParametersAsync(string? audience, CancellationToken cancellationToken)
    {
        IReadOnlyList<ValidationKey> published = await keys.GetValidationKeysAsync(cancellationToken);
        List<(SecurityKey Key, string Algorithm)> candidates = published
            .Select(k => (ToSecurityKey(k.Kid, k.PublicKey), ToSecurityAlgorithm(k.Algorithm)))
            .ToList();

        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = options.Issuer,
            ValidateAudience = true,
            ValidAudience = audience ?? options.DefaultAudience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            // IdentityModel checks lifetime against the system clock (its TimeProvider hook is not public in 8.23);
            // in production IClock is that same clock, so issuance and validation agree.
            ClockSkew = options.ClockSkew,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidTypes = [AccessTokenType],

            // Only the algorithms of the published keys (normally just the active key's ES256): no "none", no HMAC.
            ValidAlgorithms = candidates.Select(c => c.Algorithm).Distinct(StringComparer.Ordinal).ToList(),

            // The key must match the token's kid AND the token's alg must be that key's algorithm.
            TryAllIssuerSigningKeys = false,
            IssuerSigningKeyResolver = (_, securityToken, kid, _) =>
            {
                string? alg = (securityToken as JsonWebToken)?.Alg;
                return candidates.Where(c => c.Key.KeyId == kid && c.Algorithm == alg).Select(c => c.Key).ToList();
            },
        };
    }

    public async Task<TokenValidationResult> ValidateAsync(string jwt, string? audience, CancellationToken cancellationToken)
    {
        TokenValidationParameters parameters = await GetValidationParametersAsync(audience, cancellationToken);
        return await handler.ValidateTokenAsync(jwt, parameters);
    }

    public async Task<TokenValidationResult> ValidateIgnoringLifetimeAsync(string jwt, CancellationToken cancellationToken)
    {
        TokenValidationParameters parameters = await GetValidationParametersAsync(null, cancellationToken);
        parameters.ValidateLifetime = false;
        return await handler.ValidateTokenAsync(jwt, parameters);
    }

    private static void AddIfAny(Dictionary<string, object> claims, string type, IReadOnlyCollection<string> values)
    {
        if (values.Count > 0)
        {
            claims[type] = values.ToArray();
        }
    }

    /// <summary>
    /// Wraps a key object for IdentityModel. Signature-provider caching is OFF: the default factory caches providers
    /// process-wide by key id, so a provider could outlive (and reuse) a key object that the key provider has already
    /// disposed, e.g. after a reload or in a second host in the same process, and signing would fail.
    /// </summary>
    private static SecurityKey ToSecurityKey(string kid, AsymmetricAlgorithm key) => key switch
    {
        ECDsa ec => new ECDsaSecurityKey(ec) { KeyId = kid, CryptoProviderFactory = NonCachingProviders() },
        RSA rsa => new RsaSecurityKey(rsa) { KeyId = kid, CryptoProviderFactory = NonCachingProviders() },
        _ => throw new InvalidOperationException("Signing key '" + kid + "' has an unsupported key type."),
    };

    private static CryptoProviderFactory NonCachingProviders() => new() { CacheSignatureProviders = false };

    private static string ToSecurityAlgorithm(string algorithm) => algorithm switch
    {
        SigningKeyAlgorithm.ES256 => SecurityAlgorithms.EcdsaSha256,
        SigningKeyAlgorithm.RS256 => SecurityAlgorithms.RsaSha256,
        _ => throw new InvalidOperationException("Unsupported signing algorithm '" + algorithm + "'."),
    };
}
