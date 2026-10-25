using System.Diagnostics.Metrics;
using Auth.Contracts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Auth.Api.Security;

/// <summary>
/// Shared-domain mode only (T20 audit M2, cookie tossing): any host under the shared Domain can set a cookie of the same
/// name for that Domain (the <c>__Secure-</c> prefix does not stop it), and a browser then sends both. Which one the
/// server reads would depend on cookie order, so a request carrying an auth cookie name (access, refresh, XSRF-TOKEN)
/// more than once is refused with 400 before authentication. The answer also expires the host-only twins (the usual,
/// harmless cause: cookies left over from host-only mode), so a legitimate browser recovers on its next request.
/// Counted in the metric <c>auth.cookies.duplicate_rejected</c> and logged (names only, never values).
/// </summary>
internal sealed partial class DuplicateCookieGuardMiddleware(
    RequestDelegate next,
    IOptions<AuthCookieOptions> options,
    ICookieWriter cookies,
    IProblemDetailsService problemDetails,
    ILogger<DuplicateCookieGuardMiddleware> logger)
{
    private static readonly string[] GuardedNames = [AuthCookieNames.AccessWithDomain, AuthCookieNames.Refresh, AuthCookieNames.Xsrf];

    private static readonly Meter CookieMeter = new("Auth.Cookies");
    private static readonly Counter<long> DuplicatesRejected = CookieMeter.CreateCounter<long>("auth.cookies.duplicate_rejected");

    public async Task InvokeAsync(HttpContext context)
    {
        if (options.Value.Domain is not null && FindDuplicate(context.Request.Headers.Cookie) is string name)
        {
            DuplicatesRejected.Add(1);
            LogDuplicate(logger, name);
            cookies.ExpireHostOnlyTwins(context.Response);
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await problemDetails.WriteAsync(new ProblemDetailsContext
            {
                HttpContext = context,
                ProblemDetails = new ProblemDetails { Status = StatusCodes.Status400BadRequest, Title = "Conflicting authentication cookies; retry the request." },
            });
            return;
        }

        await next(context);
    }

    /// <summary>The first guarded cookie name present more than once across all Cookie headers, or null.</summary>
    internal static string? FindDuplicate(IEnumerable<string?> cookieHeaders)
    {
        Dictionary<string, int> counts = new(StringComparer.Ordinal);
        foreach (string? header in cookieHeaders)
        {
            foreach (string pair in (header ?? string.Empty).Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=', StringComparison.Ordinal);
                string cookieName = (eq < 0 ? pair : pair[..eq]).Trim();
                if (GuardedNames.Contains(cookieName, StringComparer.Ordinal))
                {
                    counts[cookieName] = counts.GetValueOrDefault(cookieName) + 1;
                    if (counts[cookieName] > 1)
                    {
                        return cookieName;
                    }
                }
            }
        }

        return null;
    }

    [LoggerMessage(EventId = 5150, Level = LogLevel.Warning, Message = "Request refused: auth cookie {CookieName} was sent more than once (shared-domain mode)")]
    private static partial void LogDuplicate(ILogger logger, string cookieName);
}
