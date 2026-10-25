namespace Auth.Api.Security;

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
