using System.Text.Json.Serialization;

namespace Auth.Contracts.Responses;

/// <summary>RFC 6749 token response of /oauth/token. The SPA keeps both tokens in memory only (never storage or cookies).</summary>
public sealed record OAuthTokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string Scheme,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("refresh_token")] string RefreshToken);

/// <summary>RFC 6749 error response of /oauth/authorize (on our domain) and /oauth/token: a code, no detail about which check failed.</summary>
public sealed record OAuthErrorResponse(
    [property: JsonPropertyName("error")] string Error);
