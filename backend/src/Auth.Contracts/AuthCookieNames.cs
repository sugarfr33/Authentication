namespace Auth.Contracts;

/// <summary>Cookie names used by the API and the auth UI.</summary>
public static class AuthCookieNames
{
    /// <summary>HttpOnly access-token cookie (host-only, Path=/).</summary>
    public const string Access = "__Host-access";

    /// <summary>HttpOnly refresh-token cookie, scoped to the refresh endpoint.</summary>
    public const string Refresh = "__Secure-refresh";

    /// <summary>Readable antiforgery cookie echoed back in the <c>X-XSRF-TOKEN</c> header.</summary>
    public const string Xsrf = "XSRF-TOKEN";
}
