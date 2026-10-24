using Auth.Contracts;
using Auth.Services.ClientApplications;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace Auth.Api.Security;

/// <summary>
/// CORS from the ClientApplication registry. A policy exists only for an allowed origin (active applications'
/// AllowedOrigin entries plus BrowserProtection:TrustedOrigins), and it lists exactly that origin with credentials.
/// There is never a wildcard. Unknown origins get no policy, so no CORS headers at all.
/// </summary>
internal sealed class ClientApplicationCorsPolicyProvider(
    IClientApplicationOriginProvider applicationOrigins,
    IOptions<BrowserProtectionOptions> options) : ICorsPolicyProvider
{
    private static readonly TimeSpan PreflightMaxAge = TimeSpan.FromMinutes(10);

    private readonly HashSet<string> trustedOrigins = BrowserProtectionMiddleware.NormalizeTrusted(options.Value.TrustedOrigins);

    public async Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        string? origin = context.Request.Headers.Origin;
        if (!OriginNormalizer.TryNormalize(origin, out string normalized))
        {
            return null;
        }

        bool allowed = trustedOrigins.Contains(normalized) || await applicationOrigins.IsAllowedAsync(normalized, context.RequestAborted);
        if (!allowed)
        {
            return null;
        }

        return new CorsPolicyBuilder()
            .WithOrigins(origin!)
            .AllowCredentials()
            .WithMethods(HttpMethods.Get, HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete)
            .WithHeaders("Content-Type", AuthCookieNames.XsrfHeader)
            .SetPreflightMaxAge(PreflightMaxAge)
            .Build();
    }
}
