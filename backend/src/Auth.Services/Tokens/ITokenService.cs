using Microsoft.IdentityModel.Tokens;

namespace Auth.Services.Tokens;

/// <summary>What goes into an access token. Built by the auth flows from the user, their roles and the client application.</summary>
/// <param name="UserId">Becomes <c>sub</c>.</param>
/// <param name="Email">Becomes <c>email</c>.</param>
/// <param name="DisplayName">Becomes <c>name</c>.</param>
/// <param name="Roles">Each becomes a <c>role</c> value.</param>
/// <param name="Permissions">Each becomes a <c>perm</c> value.</param>
/// <param name="Audience">Becomes <c>aud</c>: the client application's audience, or <see cref="TokenOptions.DefaultAudience"/>.</param>
/// <param name="ClientId">Becomes <c>client_id</c> when the token is issued for a client application.</param>
/// <param name="SessionId">Becomes <c>sid</c>: the refresh-token family, when there is one.</param>
public sealed record AccessTokenRequest(
    Guid UserId,
    string Email,
    string DisplayName,
    IReadOnlyCollection<string> Roles,
    IReadOnlyCollection<string> Permissions,
    string Audience,
    string? ClientId,
    Guid? SessionId);

/// <summary>A signed access token and when it expires.</summary>
public sealed record AccessToken(string Jwt, DateTime ExpiresUtc);

/// <summary>Issues and validates access tokens (JWT, RFC 9068 <c>at+jwt</c>).</summary>
public interface ITokenService
{
    /// <summary>Signs a token with the current signing key (ES256 by default, or RS256), valid for the configured lifetime.</summary>
    Task<AccessToken> CreateAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Validation parameters for tokens meant for <paramref name="audience"/> (default: <see cref="TokenOptions.DefaultAudience"/>).
    /// They check issuer, audience, lifetime (with at most 30 s skew), token type and signature. The signature must use
    /// a currently published key, chosen by kid, with exactly that key's algorithm. Async because the published keys
    /// come from the key provider; get fresh parameters per validation (the provider caches).
    /// </summary>
    Task<TokenValidationParameters> GetValidationParametersAsync(string? audience, CancellationToken cancellationToken);

    /// <summary>Validates a token with <see cref="GetValidationParametersAsync"/>.</summary>
    Task<TokenValidationResult> ValidateAsync(string jwt, string? audience, CancellationToken cancellationToken);

    /// <summary>
    /// Like <see cref="ValidateAsync"/> for the default audience, but an expired token is still accepted: signature,
    /// issuer, audience, type and algorithm are all checked. Only for logout, so a session whose access token has
    /// just expired can still be ended; never for authorization.
    /// </summary>
    Task<TokenValidationResult> ValidateIgnoringLifetimeAsync(string jwt, CancellationToken cancellationToken);
}
