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

/// <summary>
/// RP-initiated logout confirmed by the signed-in user (<c>POST /oauth/logout</c>, JSON, same names as the query of
/// <c>GET /oauth/logout</c>). Ends the user's sessions at that application only.
/// </summary>
public sealed record OAuthLogoutRequest(
    [property: System.Text.Json.Serialization.JsonPropertyName("client_id")] string? ClientId,
    [property: System.Text.Json.Serialization.JsonPropertyName("post_logout_redirect_uri")] string? PostLogoutRedirectUri,
    [property: System.Text.Json.Serialization.JsonPropertyName("state")] string? State);
