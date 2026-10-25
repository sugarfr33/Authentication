namespace Auth.Contracts;

/// <summary>Cookie and header names used by the API and the auth UI.</summary>
public static class AuthCookieNames
{
    /// <summary>HttpOnly access-token cookie: host-only (no Domain), Path=/, Secure.</summary>
    public const string Access = "__Host-access";

    /// <summary>
    /// Access-token cookie name when a cookie Domain is configured (shared-domain mode, T20). The <c>__Host-</c> prefix
    /// forbids a Domain attribute, so the <c>__Secure-</c> prefix is used instead.
    /// </summary>
    public const string AccessWithDomain = "__Secure-access";

    /// <summary>HttpOnly refresh-token cookie, scoped to the refresh endpoint path.</summary>
    public const string Refresh = "__Secure-refresh";

    /// <summary>Readable (not HttpOnly, by design) antiforgery request token, echoed back in <see cref="XsrfHeader"/>.</summary>
    public const string Xsrf = "XSRF-TOKEN";

    /// <summary>HttpOnly antiforgery cookie token that the request token is checked against.</summary>
    public const string Antiforgery = "__Host-antiforgery";

    /// <summary>
    /// HttpOnly MFA login challenge (T21): password proven, second factor pending. Host-only, Path /api/v1/auth/mfa, 5
    /// minutes. <c>__Secure-</c>, not <c>__Host-</c>, because <c>__Host-</c> requires Path=/.
    /// </summary>
    public const string MfaChallenge = "__Secure-mfa";

    /// <summary>Header that state-changing requests must carry with the value of the <see cref="Xsrf"/> cookie.</summary>
    public const string XsrfHeader = "X-XSRF-TOKEN";
}
