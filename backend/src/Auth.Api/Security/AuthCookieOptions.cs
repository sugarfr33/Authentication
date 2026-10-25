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
