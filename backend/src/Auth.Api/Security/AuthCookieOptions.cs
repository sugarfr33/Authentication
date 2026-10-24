namespace Auth.Api.Security;

/// <summary>Cookie transport settings (configuration section <c>AuthCookies</c>).</summary>
public sealed class AuthCookieOptions
{
    public const string SectionName = "AuthCookies";

    /// <summary>
    /// Cookie Domain for shared-domain mode (T20). Null (the default) keeps cookies host-only, which allows the stricter
    /// <c>__Host-</c> prefix on the access cookie; with a Domain the access cookie is <c>__Secure-access</c>.
    /// </summary>
    public string? Domain { get; set; }

    /// <summary>SameSite for the access cookie: Lax (default) or Strict. None is refused.</summary>
    public SameSiteMode AccessSameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>The only path the refresh cookie is sent to.</summary>
    public string RefreshPath { get; set; } = "/api/v1/auth/refresh";

    internal bool IsValid() =>
        AccessSameSite is SameSiteMode.Lax or SameSiteMode.Strict
        && RefreshPath.StartsWith('/')
        && (Domain is null || (Domain.Length > 0 && !Domain.Contains('/', StringComparison.Ordinal) && !Domain.Contains(':', StringComparison.Ordinal)));
}

/// <summary>Browser request protections (configuration section <c>BrowserProtection</c>).</summary>
public sealed class BrowserProtectionOptions
{
    public const string SectionName = "BrowserProtection";

    /// <summary>
    /// Extra origins allowed for CORS and state-changing requests besides active client applications, e.g. the auth UI
    /// origin. Exact origins only (<c>https://host[:port]</c>); wildcards are refused.
    /// </summary>
    public IList<string> TrustedOrigins { get; } = [];

    /// <summary>
    /// When true, a state-changing request with neither Origin nor Referer passes the origin check (non-browser
    /// clients). It still needs a valid antiforgery token. Default false: such requests are rejected.
    /// </summary>
    public bool AllowMissingOrigin { get; set; }
}
