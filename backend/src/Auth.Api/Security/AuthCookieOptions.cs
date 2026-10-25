using System.Net;

namespace Auth.Api.Security;

/// <summary>Cookie transport settings (configuration section <c>AuthCookies</c>).</summary>
public sealed class AuthCookieOptions
{
    public const string SectionName = "AuthCookies";

    /// <summary>
    /// Cookie Domain for shared-domain mode (T20, docs/single-logout-and-shared-domain.md). Null or empty (the default):
    /// host-only cookies, with the stricter <c>__Host-</c> prefix on the access cookie. Set (for example
    /// <c>example.com</c> for an API at <c>auth.example.com</c>): the access cookie is <c>__Secure-access</c>, and the
    /// access, refresh and XSRF-TOKEN cookies carry this Domain. Checked at startup by <see cref="CookieDomainRules"/>.
    /// </summary>
    public string? Domain { get; set; }

    /// <summary>SameSite for the access cookie: Lax (default) or Strict. None is refused.</summary>
    public SameSiteMode AccessSameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>
    /// The only path the refresh cookie is sent to: the auth endpoints, so /refresh can rotate it and /logout and /login
    /// can end the session it belongs to even after the access cookie has expired. No other route reads it.
    /// </summary>
    public string RefreshPath { get; set; } = "/api/v1/auth";

    internal bool IsValid(string? issuer) =>
        AccessSameSite is SameSiteMode.Lax or SameSiteMode.Strict
        && RefreshPath.StartsWith('/')
        && (Domain is null || CookieDomainRules.IsAllowed(Domain, issuer));
}

/// <summary>
/// Conservative rules for the shared-domain cookie Domain (no public-suffix list is available without a package):
/// <list type="bullet">
/// <item>a bare lower-case DNS name: no scheme, port, path, leading or trailing dot, no IP address;</item>
/// <item>at least two labels of 1 to 63 characters (a-z, 0-9, hyphen inside), at most 253 characters, a non-numeric
/// top-level label;</item>
/// <item>not a known two-label public suffix shape (<c>co.uk</c>, <c>com.au</c>, ...: a common second-level label
/// under a two-letter country code);</item>
/// <item>the auth host (from Auth:Issuer, which must be https) is the Domain itself or a subdomain of it.</item>
/// </list>
/// A Domain that passes can still be a public suffix this list does not know (for example a hosting provider's shared
/// domain): choose a domain you own.
/// </summary>
internal static class CookieDomainRules
{
    private static readonly HashSet<string> SecondLevelSuffixLabels = new(StringComparer.Ordinal)
    {
        "ac", "co", "com", "edu", "gen", "go", "gob", "gov", "gv", "id", "info", "lg", "ltd", "me", "mil", "ne", "net",
        "nhs", "nic", "nom", "or", "org", "plc", "sch", "web",
    };

    public static bool IsAllowed(string domain, string? issuer)
    {
        if (domain.Length is 0 or > 253
            || !string.Equals(domain, domain.ToLowerInvariant(), StringComparison.Ordinal)
            || domain.StartsWith('.') || domain.EndsWith('.')
            || IPAddress.TryParse(domain, out _))
        {
            return false;
        }

        string[] labels = domain.Split('.');
        if (labels.Length < 2 || !labels.All(IsLabel) || labels[^1].All(char.IsAsciiDigit))
        {
            return false;
        }

        if (labels.Length == 2 && labels[1].Length == 2 && SecondLevelSuffixLabels.Contains(labels[0]))
        {
            return false;
        }

        return Uri.TryCreate(issuer, UriKind.Absolute, out Uri? auth)
            && auth.Scheme == Uri.UriSchemeHttps
            && (auth.Host == domain || auth.Host.EndsWith("." + domain, StringComparison.Ordinal));
    }

    private static bool IsLabel(string label) =>
        label.Length is >= 1 and <= 63
        && label.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-')
        && !label.StartsWith('-') && !label.EndsWith('-');
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
