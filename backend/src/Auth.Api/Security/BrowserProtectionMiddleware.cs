using Auth.Contracts;
using Auth.Services.ClientApplications;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Auth.Api.Security;

/// <summary>
/// CSRF defence for cookie-authenticated browsers:
/// <list type="bullet">
/// <item>GET/HEAD under /api issue the antiforgery pair: an HttpOnly cookie token plus the readable
/// <c>XSRF-TOKEN</c> cookie that script echoes back.</item>
/// <item>Every other method (POST, PUT, PATCH, DELETE, ...) must come from an allowed origin: Origin header, or Referer
/// when Origin is absent; same-origin, configured trusted origins or active client applications. It must also carry a
/// matching <c>X-XSRF-TOKEN</c> header.</item>
/// </list>
/// Runs after authentication, because antiforgery tokens are bound to the signed-in user.
/// </summary>
internal sealed class BrowserProtectionMiddleware(
    RequestDelegate next,
    IAntiforgery antiforgery,
    IClientApplicationOriginProvider applicationOrigins,
    IOptions<BrowserProtectionOptions> options,
    IProblemDetailsService problemDetails,
    IHostEnvironment environment)
{
    private static readonly PathString ApiPrefix = new("/api");

    private readonly HashSet<string> trustedOrigins = NormalizeTrusted(options.Value.TrustedOrigins, requireHttps: !environment.IsDevelopment());

    public async Task InvokeAsync(HttpContext context)
    {
        string method = context.Request.Method;
        if (HttpMethods.IsGet(method) || HttpMethods.IsHead(method))
        {
            if (context.Request.Path.StartsWithSegments(ApiPrefix))
            {
                IssueTokens(context, antiforgery);
            }

            await next(context);
            return;
        }

        if (HttpMethods.IsOptions(method))
        {
            await next(context);
            return;
        }

        if (!await IsOriginAllowedAsync(context))
        {
            await WriteProblemAsync(context, StatusCodes.Status403Forbidden, "Request origin is not allowed.");
            return;
        }

        // Endpoints that use no cookie (/oauth/token: the code plus the PKCE verifier, or the refresh token, is the
        // credential, and the endpoint itself requires the client's own registered Origin) declare DisableAntiforgery();
        // antiforgery, bound to a cookie session, does not apply there. The origin check above still does.
        if (context.GetEndpoint()?.Metadata.GetMetadata<IAntiforgeryMetadata>() is { RequiresValidation: false })
        {
            await next(context);
            return;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, "Missing or invalid antiforgery token.");
            return;
        }

        await next(context);
    }

    /// <summary>True when the request's origin is allowed for a state-changing call. Used by the CORS policy too.</summary>
    internal async Task<bool> IsOriginAllowedAsync(HttpContext context)
    {
        string? origin = context.Request.Headers.Origin;
        string candidate;
        if (!string.IsNullOrEmpty(origin))
        {
            if (!OriginNormalizer.TryNormalize(origin, out candidate))
            {
                return false;
            }
        }
        else if (!string.IsNullOrEmpty(context.Request.Headers.Referer))
        {
            if (!OriginNormalizer.TryGetOrigin(context.Request.Headers.Referer, out candidate))
            {
                return false;
            }
        }
        else
        {
            return options.Value.AllowMissingOrigin;
        }

        string self = (context.Request.Scheme + "://" + context.Request.Host.Value).ToLowerInvariant();
        return candidate == self
            || trustedOrigins.Contains(candidate)
            || await applicationOrigins.IsAllowedAsync(candidate, context.RequestAborted);
    }

    internal static HashSet<string> NormalizeTrusted(IEnumerable<string> configured, bool requireHttps)
    {
        HashSet<string> origins = new(StringComparer.Ordinal);
        foreach (string entry in configured)
        {
            if (!OriginNormalizer.TryNormalize(entry, requireHttps, out string normalized))
            {
                throw new InvalidOperationException(
                    "BrowserProtection:TrustedOrigins entries must be exact origins; outside Development they must be https (http only for localhost).");
            }

            origins.Add(normalized);
        }

        return origins;
    }

    /// <summary>
    /// Issues a fresh antiforgery pair for <c>context.User</c>: the HttpOnly cookie token plus the readable XSRF-TOKEN.
    /// Tokens are bound to the user, so login and logout call this again after switching the user.
    /// </summary>
    internal static void IssueTokens(HttpContext context, IAntiforgery antiforgery)
    {
        AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(context);

        // Shared-domain mode (T20): the SPA on a sibling subdomain must be able to read the request token, so it gets the
        // cookie Domain too. The HttpOnly antiforgery cookie it is checked against stays host-only on the API.
        string? domain = context.RequestServices.GetService<IOptions<AuthCookieOptions>>()?.Value.Domain;
        if (domain is not null)
        {
            // Expire a host-only XSRF-TOKEN twin first (left over from host-only mode), so the SPA never reads a stale one.
            context.Response.Cookies.Append(AuthCookieNames.Xsrf, string.Empty, new CookieOptions
            {
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Expires = DateTimeOffset.UnixEpoch,
            });
        }

        context.Response.Cookies.Append(AuthCookieNames.Xsrf, tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            Domain = domain,
            IsEssential = true,
        });
    }

    private async Task WriteProblemAsync(HttpContext context, int status, string title)
    {
        context.Response.StatusCode = status;
        await problemDetails.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = new ProblemDetails { Status = status, Title = title },
        });
    }
}
