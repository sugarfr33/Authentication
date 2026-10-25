using Auth.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Auth.Client;

/// <summary>Names shared by the client extension and its hosts.</summary>
public static class CentralAuthDefaults
{
    /// <summary>The authentication scheme <c>AddCentralAuth</c> registers (and makes the default).</summary>
    public const string AuthenticationScheme = "CentralAuth";

    /// <summary>The named <see cref="HttpClient"/> that fetches the JWKS; configure it to add a proxy or a handler.</summary>
    public const string JwksHttpClientName = "CentralAuth.Jwks";

    /// <summary>The JWKS location relative to the issuer (central auth's <c>/.well-known/jwks.json</c>).</summary>
    public const string JwksPath = "/.well-known/jwks.json";
}

/// <summary>
/// How a resource server accepts central-auth access tokens (docs/t22-client-extension.md section 3). Validated at
/// startup: a misconfigured API does not start.
/// </summary>
public sealed class CentralAuthOptions : AuthenticationSchemeOptions
{
    /// <summary>Must equal the token's <c>iss</c> (central auth's <c>Auth:Issuer</c>). Required, absolute URI.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Must equal the token's <c>aud</c>: the client application's audience, or central auth's default audience in
    /// cookie mode. Required.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Set: the token's <c>client_id</c> must be present and equal (ordinal). Null: the token must carry no
    /// <c>client_id</c> (a browser-session token).
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>The JWKS URI; default <see cref="Issuer"/> plus <see cref="CentralAuthDefaults.JwksPath"/>.</summary>
    public Uri? JwksUri { get; set; }

    /// <summary>Https is required for the JWKS unless this is false (local development only).</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>Accept <c>Authorization: Bearer</c>. When the header is present, the cookie is never consulted.</summary>
    public bool AcceptBearer { get; set; } = true;

    /// <summary>Accept the access cookie (shared-domain mode only; docs section 6). Requires <see cref="ClientId"/> null.</summary>
    public bool AcceptCookie { get; set; }

    /// <summary>The access cookie read in cookie mode.</summary>
    public string CookieName { get; set; } = AuthCookieNames.AccessWithDomain;

    /// <summary>Tolerance for <c>exp</c> and <c>nbf</c>; 0 to 5 minutes.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>A cached JWKS older than this is refreshed on the next request (central auth sends max-age=300).</summary>
    public TimeSpan JwksRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>At most one JWKS fetch per interval for a refresh the cache did not plan (unknown kid, failures).</summary>
    public TimeSpan JwksMinRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>When refreshes keep failing, the last good JWKS is used at most this long; then requests fail closed.</summary>
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

    public ValidateOptionsResult Validate(string? name, CentralAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        List<string> failures = [];
        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
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

        if (options.JwksUri is not { IsAbsoluteUri: true } jwks)
        {
            failures.Add("CentralAuth:JwksUri must be an absolute URI.");
        }
        else if (options.RequireHttpsMetadata && jwks.Scheme != Uri.UriSchemeHttps)
        {
            failures.Add("CentralAuth:JwksUri must use https (set RequireHttpsMetadata false for local development only).");
        }

        if (!options.AcceptBearer && !options.AcceptCookie)
        {
            failures.Add("CentralAuth: accept the Bearer header, the cookie, or both.");
        }

        if (options.AcceptCookie && options.ClientId is not null)
        {
            failures.Add("CentralAuth: the access cookie carries a browser-session token (no client_id); AcceptCookie needs ClientId null.");
        }

        if (options.AcceptCookie && string.IsNullOrWhiteSpace(options.CookieName))
        {
            failures.Add("CentralAuth:CookieName is required in cookie mode.");
        }

        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > MaxClockSkew)
        {
            failures.Add("CentralAuth:ClockSkew must be between 0 and 5 minutes.");
        }

        if (options.JwksMinRefreshInterval <= TimeSpan.Zero || options.JwksRefreshInterval < options.JwksMinRefreshInterval)
        {
            failures.Add("CentralAuth: JwksMinRefreshInterval must be positive and at most JwksRefreshInterval.");
        }

        if (options.JwksMaxStaleness < options.JwksRefreshInterval)
        {
            failures.Add("CentralAuth:JwksMaxStaleness must be at least JwksRefreshInterval.");
        }

        if (options.JwksFetchTimeout < TimeSpan.FromSeconds(1) || options.JwksFetchTimeout > TimeSpan.FromMinutes(1))
        {
            failures.Add("CentralAuth:JwksFetchTimeout must be between 1 second and 1 minute.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
