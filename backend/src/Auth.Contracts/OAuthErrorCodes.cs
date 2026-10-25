namespace Auth.Contracts;

/// <summary>
/// The OAuth error codes the authorization server answers (RFC 6749 sections 4.1.2.1 and 5.2, plus the two on our own
/// domain). Shared by the server and its client libraries; the answer never says which check failed.
/// </summary>
public static class OAuthErrorCodes
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnsupportedResponseType = "unsupported_response_type";
    public const string UnsupportedGrantType = "unsupported_grant_type";
    public const string AccessDenied = "access_denied";

    /// <summary>RFC 6749 4.1.2.1: the server could not complete the request (nothing that would leak why).</summary>
    public const string ServerError = "server_error";

    /// <summary>Not RFC 6749: the redirect URI is not registered, so the error is shown on our domain (never redirected).</summary>
    public const string InvalidRedirectUri = "invalid_redirect_uri";

    /// <summary>RFC 6750 3.1: a resource server refused the access token (any reason; the answer never says which).</summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>OpenID Connect: no browser session and no login UI configured.</summary>
    public const string LoginRequired = "login_required";
}
