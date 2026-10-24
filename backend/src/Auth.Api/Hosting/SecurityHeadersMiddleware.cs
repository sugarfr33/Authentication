using Microsoft.Net.Http.Headers;

namespace Auth.Api.Hosting;

/// <summary>
/// Security headers on every response (errors included), set when the response starts. See docs/security-headers.md,
/// including the different CSP the Vue app will need.
/// </summary>
internal sealed class SecurityHeadersMiddleware(RequestDelegate next, IHostEnvironment environment)
{
    /// <summary>The API serves JSON only, so nothing may load, frame, or be framed.</summary>
    public const string ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    public const string StrictTransportSecurity = "max-age=31536000; includeSubDomains";

    public const string ReferrerPolicy = "no-referrer";

    public const string PermissionsPolicy =
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), " +
        "gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), " +
        "publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=()";

    /// <summary>Default for any response that does not set its own caching (auth responses must never be cached).</summary>
    public const string NoStore = "no-store";

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            Apply(context);
            return Task.CompletedTask;
        });

        return next(context);
    }

    private void Apply(HttpContext context)
    {
        IHeaderDictionary headers = context.Response.Headers;
        headers[HeaderNames.XContentTypeOptions] = "nosniff";
        headers[HeaderNames.ContentSecurityPolicy] = ContentSecurityPolicy;
        headers[HeaderNames.XFrameOptions] = "DENY";
        headers["Referrer-Policy"] = ReferrerPolicy;
        headers["Permissions-Policy"] = PermissionsPolicy;
        headers["Cross-Origin-Opener-Policy"] = "same-origin";

        // HSTS only means something over HTTPS, and local development must stay able to use plain http.
        if (context.Request.IsHttps && !environment.IsDevelopment())
        {
            headers[HeaderNames.StrictTransportSecurity] = StrictTransportSecurity;
        }

        // CORS answers are computed per request Origin (one exact origin per policy), so caches must key on Origin;
        // the CORS middleware only adds this itself when a policy lists several origins.
        if (!headers.Vary.ToString().Contains("Origin", StringComparison.OrdinalIgnoreCase))
        {
            headers.Append(HeaderNames.Vary, "Origin");
        }

        if (!headers.ContainsKey(HeaderNames.CacheControl))
        {
            headers[HeaderNames.CacheControl] = NoStore;
            headers[HeaderNames.Pragma] = "no-cache";
        }
    }
}
