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

    /// <summary>Expires both cookies (logout) with the same name, path, domain and flags they were set with.</summary>
    void ClearAuthCookies(HttpResponse response);
}

internal sealed class CookieWriter(IOptions<AuthCookieOptions> options, IClock clock) : ICookieWriter
{
    private readonly AuthCookieOptions settings = options.Value;

    public string AccessCookieName => settings.Domain is null ? AuthCookieNames.Access : AuthCookieNames.AccessWithDomain;

    public void WriteAccessToken(HttpResponse response, AccessToken token)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(token);
        response.Cookies.Append(AccessCookieName, token.Jwt, AccessCookie(Remaining(token.ExpiresUtc)));
    }

    public void WriteRefreshToken(HttpResponse response, IssuedRefreshToken token)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(token);
        response.Cookies.Append(AuthCookieNames.Refresh, token.Token, RefreshCookie(Remaining(token.ExpiresUtc)));
    }

    public void ClearAuthCookies(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Cookies.Append(AccessCookieName, string.Empty, Expired(AccessCookie(TimeSpan.Zero)));
        response.Cookies.Append(AuthCookieNames.Refresh, string.Empty, Expired(RefreshCookie(TimeSpan.Zero)));
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
