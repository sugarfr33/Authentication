namespace Auth.Contracts.Requests;

/// <summary>Authorization-code request (<c>/oauth/authorize</c>) using PKCE.</summary>
public sealed record AuthorizeRequest(
    string ClientId,
    string RedirectUri,
    string ResponseType,
    string CodeChallenge,
    string CodeChallengeMethod,
    string? State,
    string? Scope);

/// <summary>Exchange of an authorization code for a session (<c>/oauth/token</c>).</summary>
public sealed record TokenExchangeRequest(
    string GrantType,
    string Code,
    string RedirectUri,
    string ClientId,
    string CodeVerifier);
