using Auth.Contracts;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.Extensions.Options;

namespace Auth.Api.Security;

/// <summary>
/// The only way tokens leave the API: HttpOnly, Secure cookies. Response bodies, URLs and script-readable headers
/// never carry them.
/// </summary>
public interface ICookieWriter
{
    /// <summary>The access cookie name: <c>__Host-access</c>, or <c>__Secure-access</c> when a Domain is configured.</summary>
    string AccessCookieName { get; }

    /// <summary>HttpOnly, Secure, SameSite Lax (or Strict), Path=/, Max-Age = remaining token lifetime.</summary>
    void WriteAccessToken(HttpResponse response, AccessToken token);

    /// <summary>HttpOnly, Secure, SameSite Strict, Path = the refresh endpoint, Max-Age = remaining refresh lifetime.</summary>
    void WriteRefreshToken(HttpResponse response, IssuedRefreshToken token);

    /// <summary>
    /// Expires both cookies (logout) with the same name, path, domain and flags they were set with. In shared-domain mode
    /// the host-only variants are expired as well, so a browser that still holds cookies from before a mode switch is
    /// signed out completely.
    /// </summary>
    void ClearAuthCookies(HttpResponse response);

    /// <summary>Shared-domain mode: expires the host-only access, refresh and XSRF-TOKEN cookies (no-op in host-only mode).</summary>
    void ExpireHostOnlyTwins(HttpResponse response);

    /// <summary>The MFA login challenge (T21): HttpOnly, Secure, SameSite Strict, host-only, Path /api/v1/auth/mfa.</summary>
    void WriteMfaChallenge(HttpResponse response, string challenge, TimeSpan lifetime);

    /// <summary>Expires the MFA login challenge cookie.</summary>
    void ClearMfaChallenge(HttpResponse response);
}

internal sealed class CookieWriter(IOptions<AuthCookieOptions> options, IClock clock) : ICookieWriter
{
    public const string MfaChallengePath = "/api/v1/auth/mfa";

    private readonly AuthCookieOptions settings = options.Value;

    public string AccessCookieName => settings.Domain is null ? AuthCookieNames.Access : AuthCookieNames.AccessWithDomain;

    public void WriteAccessToken(HttpResponse response, AccessToken token)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(token);
        ExpireHostOnlyTwin(response, AuthCookieNames.Access, AccessCookie(TimeSpan.Zero));
        response.Cookies.Append(AccessCookieName, token.Jwt, AccessCookie(Remaining(token.ExpiresUtc)));
    }

    public void WriteRefreshToken(HttpResponse response, IssuedRefreshToken token)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(token);
        ExpireHostOnlyTwin(response, AuthCookieNames.Refresh, RefreshCookie(TimeSpan.Zero));
        response.Cookies.Append(AuthCookieNames.Refresh, token.Token, RefreshCookie(Remaining(token.ExpiresUtc)));
    }

    public void ClearAuthCookies(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ExpireHostOnlyTwin(response, AuthCookieNames.Access, AccessCookie(TimeSpan.Zero));
        ExpireHostOnlyTwin(response, AuthCookieNames.Refresh, RefreshCookie(TimeSpan.Zero));
        response.Cookies.Append(AccessCookieName, string.Empty, Expired(AccessCookie(TimeSpan.Zero)));
        response.Cookies.Append(AuthCookieNames.Refresh, string.Empty, Expired(RefreshCookie(TimeSpan.Zero)));
    }

    public void WriteMfaChallenge(HttpResponse response, string challenge, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Cookies.Append(AuthCookieNames.MfaChallenge, challenge, MfaCookie(lifetime));
    }

    public void ClearMfaChallenge(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Cookies.Append(AuthCookieNames.MfaChallenge, string.Empty, Expired(MfaCookie(TimeSpan.Zero)));
    }

    /// <summary>Host-only in both modes: only this API reads it, on the MFA paths.</summary>
    private static CookieOptions MfaCookie(TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = MfaChallengePath,
        MaxAge = maxAge,
        IsEssential = true,
    };

    public void ExpireHostOnlyTwins(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ExpireHostOnlyTwin(response, AuthCookieNames.Access, AccessCookie(TimeSpan.Zero));
        ExpireHostOnlyTwin(response, AuthCookieNames.Refresh, RefreshCookie(TimeSpan.Zero));
        ExpireHostOnlyTwin(response, AuthCookieNames.Xsrf, new CookieOptions { Secure = true, SameSite = SameSiteMode.Strict, Path = "/" });
    }

    /// <summary>
    /// Shared-domain mode only (T20 review M1): every time a cookie is written with the Domain, the host-only cookie of
    /// the same name (left over from host-only mode) is expired first, so the browser never sends two cookies of one name
    /// (a stale refresh token sent first would trigger reuse detection). Written BEFORE the Domain cookie.
    /// </summary>
    private void ExpireHostOnlyTwin(HttpResponse response, string name, CookieOptions template)
    {
        if (settings.Domain is null)
        {
            return;
        }

        CookieOptions hostOnly = Expired(template);
        hostOnly.Domain = null;
        response.Cookies.Append(name, string.Empty, hostOnly);
    }

    private CookieOptions AccessCookie(TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = settings.AccessSameSite,
        Path = "/",
        Domain = settings.Domain,
        MaxAge = maxAge,
        IsEssential = true,
    };

    private CookieOptions RefreshCookie(TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = settings.RefreshPath,
        Domain = settings.Domain,
        MaxAge = maxAge,
        IsEssential = true,
    };

    private static CookieOptions Expired(CookieOptions cookie)
    {
        cookie.Expires = DateTimeOffset.UnixEpoch;
        return cookie;
    }

    private TimeSpan Remaining(DateTime expiresUtc)
    {
        TimeSpan remaining = expiresUtc - clock.UtcNow;
        return remaining > TimeSpan.Zero ? TimeSpan.FromSeconds(Math.Round(remaining.TotalSeconds)) : TimeSpan.Zero;
    }
}
