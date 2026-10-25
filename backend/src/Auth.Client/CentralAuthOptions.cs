using Auth.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Auth.Client;

/// <summary>Anchor type used by architecture tests to locate this assembly.</summary>
public static class AssemblyMarker;

/// <summary>Names shared by the client extension and its hosts.</summary>
public static class CentralAuthDefaults
{
    /// <summary>The authentication scheme <c>AddCentralAuth</c> registers (and makes the default).</summary>
    public const string AuthenticationScheme = "CentralAuth";

    /// <summary>
    /// The named <see cref="HttpClient"/> that fetches the JWKS. Its primary handler never follows redirects; a host may
    /// add handlers (a proxy, logging) but must not turn redirects back on.
    /// </summary>
    public const string JwksHttpClientName = "CentralAuth.Jwks";

    /// <summary>The JWKS location relative to the issuer (central auth's <c>/.well-known/jwks.json</c>).</summary>
    public const string JwksPath = "/.well-known/jwks.json";
}

/// <summary>
/// How a resource server accepts central-auth access tokens (docs/t22-client-extension.md section 3). Validated at
/// startup: a misconfigured API does not start. Read once per scheme: a change needs a restart.
/// </summary>
public sealed class CentralAuthOptions : AuthenticationSchemeOptions
{
    /// <summary>Must equal the token's <c>iss</c> (central auth's <c>Auth:Issuer</c>). Required, absolute URI.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Must equal the token's <c>aud</c>: this API's own audience (one per API; see docs section 6 on the shared cookie
    /// audience), or central auth's default audience in cookie mode. Required.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Set: the token's <c>client_id</c> must be present (once) and equal (ordinal). Null: the token must carry no
    /// <c>client_id</c> (a browser-session token).
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>The JWKS URI; default <see cref="Issuer"/> plus <see cref="CentralAuthDefaults.JwksPath"/>. Same host as the issuer unless <see cref="AllowForeignJwksHost"/>.</summary>
    public Uri? JwksUri { get; set; }

    /// <summary>Allow a JWKS on another host than the issuer's (for example a CDN). Off by default.</summary>
    public bool AllowForeignJwksHost { get; set; }

    /// <summary>Https is required for the JWKS and the allowed origins unless this is false (local development only).</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>Accept <c>Authorization: Bearer</c>. When the header is present, the cookie is never consulted.</summary>
    public bool AcceptBearer { get; set; } = true;

    /// <summary>Accept the access cookie (shared-domain mode only; docs section 6). Requires <see cref="ClientId"/> null and <see cref="AllowedOrigins"/>.</summary>
    public bool AcceptCookie { get; set; }

    /// <summary>The access cookie read in cookie mode; must start with <c>__Secure-</c> or <c>__Host-</c>.</summary>
    public string CookieName { get; set; } = AuthCookieNames.AccessWithDomain;

    /// <summary>
    /// Cookie mode: the origins (<c>https://app.example.com</c>) whose pages may send state-changing cookie requests.
    /// An unsafe cookie request needs an <c>Origin</c> header in this list, and is refused when Sec-Fetch-Site says cross-site.
    /// </summary>
    public IList<string> AllowedOrigins { get; } = [];

    /// <summary>Tolerance for <c>exp</c> and <c>nbf</c>; 0 to 5 minutes.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>A cached JWKS older than this is refreshed in the background (central auth sends max-age=300); at most 24 h.</summary>
    public TimeSpan JwksRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>At most one JWKS fetch per interval for a refresh the cache did not plan (unknown kid, failures).</summary>
    public TimeSpan JwksMinRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// When refreshes keep failing, the last good JWKS is used at most this long after it was fetched, then requests fail
    /// closed. At most 24 h; a removed (compromised) key stays trusted this long while the JWKS cannot be fetched.
    /// </summary>
    public TimeSpan JwksMaxStaleness { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Timeout of one JWKS fetch.</summary>
    public TimeSpan JwksFetchTimeout { get; set; } = TimeSpan.FromSeconds(10);
}

/// <summary>Fills <see cref="CentralAuthOptions.JwksUri"/> from the issuer when it is not set.</summary>
internal sealed class CentralAuthPostConfigure : IPostConfigureOptions<CentralAuthOptions>
{
    public void PostConfigure(string? name, CentralAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.JwksUri is null && Uri.TryCreate(options.Issuer.TrimEnd('/') + CentralAuthDefaults.JwksPath, UriKind.Absolute, out Uri? jwks))
        {
            options.JwksUri = jwks;
        }
    }
}

/// <summary>The startup checks of <see cref="CentralAuthOptions"/> (run by ValidateOnStart).</summary>
internal sealed class CentralAuthOptionsValidator : IValidateOptions<CentralAuthOptions>
{
    private static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxCacheAge = TimeSpan.FromHours(24);

    public ValidateOptionsResult Validate(string? name, CentralAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        List<string> failures = [];
        Uri? issuer = Uri.TryCreate(options.Issuer, UriKind.Absolute, out Uri? parsed) ? parsed : null;
        if (issuer is null)
        {
            failures.Add("CentralAuth:Issuer must be an absolute URI.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add("CentralAuth:Audience is required.");
        }

        if (options.ClientId is not null && string.IsNullOrWhiteSpace(options.ClientId))
        {
            failures.Add("CentralAuth:ClientId must be null or a client id.");
        }

        ValidateJwksUri(options, issuer, failures);

        if (!options.AcceptBearer && !options.AcceptCookie)
        {
            failures.Add("CentralAuth: accept the Bearer header, the cookie, or both.");
        }

        if (options.AcceptCookie)
        {
            ValidateCookieMode(options, failures);
        }

        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > MaxClockSkew)
        {
            failures.Add("CentralAuth:ClockSkew must be between 0 and 5 minutes.");
        }

        if (options.JwksMinRefreshInterval <= TimeSpan.Zero || options.JwksRefreshInterval < options.JwksMinRefreshInterval || options.JwksRefreshInterval > MaxCacheAge)
        {
            failures.Add("CentralAuth: JwksMinRefreshInterval must be positive and at most JwksRefreshInterval, which is at most 24 hours.");
        }

        if (options.JwksMaxStaleness < options.JwksRefreshInterval || options.JwksMaxStaleness > MaxCacheAge)
        {
            failures.Add("CentralAuth:JwksMaxStaleness must be between JwksRefreshInterval and 24 hours.");
        }

        if (options.JwksFetchTimeout < TimeSpan.FromSeconds(1) || options.JwksFetchTimeout > TimeSpan.FromMinutes(1))
        {
            failures.Add("CentralAuth:JwksFetchTimeout must be between 1 second and 1 minute.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateJwksUri(CentralAuthOptions options, Uri? issuer, List<string> failures)
    {
        if (options.JwksUri is not { IsAbsoluteUri: true } jwks)
        {
            failures.Add("CentralAuth:JwksUri must be an absolute URI.");
            return;
        }

        if (!(jwks.Scheme == Uri.UriSchemeHttps || (jwks.Scheme == Uri.UriSchemeHttp && !options.RequireHttpsMetadata)))
        {
            failures.Add("CentralAuth:JwksUri must use https (http only with RequireHttpsMetadata false, for local development).");
        }

        if (jwks.UserInfo.Length > 0)
        {
            failures.Add("CentralAuth:JwksUri must not contain user information.");
        }

        if (!options.AllowForeignJwksHost && issuer is not null && !string.Equals(jwks.IdnHost, issuer.IdnHost, StringComparison.OrdinalIgnoreCase))
        {
            failures.Add("CentralAuth:JwksUri must be on the issuer's host (set AllowForeignJwksHost to allow another host).");
        }
    }

    private static void ValidateCookieMode(CentralAuthOptions options, List<string> failures)
    {
        if (options.ClientId is not null)
        {
            failures.Add("CentralAuth: the access cookie carries a browser-session token (no client_id); AcceptCookie needs ClientId null.");
        }

        if (!(options.CookieName.StartsWith("__Secure-", StringComparison.Ordinal) || options.CookieName.StartsWith("__Host-", StringComparison.Ordinal)))
        {
            failures.Add("CentralAuth:CookieName must start with __Secure- or __Host- in cookie mode.");
        }

        if (options.AllowedOrigins.Count == 0)
        {
            failures.Add("CentralAuth:AllowedOrigins is required in cookie mode (the pages that may send state-changing requests).");
        }

        foreach (string origin in options.AllowedOrigins)
        {
            if (OriginRules.Normalize(origin, options.RequireHttpsMetadata) is null)
            {
                failures.Add("CentralAuth:AllowedOrigins entries must be origins such as https://app.example.com (no path, query or user information).");
                break;
            }
        }
    }
}

/// <summary>Origin comparison for the cookie-mode CSRF check.</summary>
internal static class OriginRules
{
    /// <summary>scheme://host[:port] in lower case, or null when <paramref name="value"/> is not a plain origin.</summary>
    public static string? Normalize(string? value, bool requireHttps)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
            || uri.UserInfo.Length > 0
            || uri.AbsolutePath != "/"
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && !requireHttps)))
        {
            return null;
        }

        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
    }
}
