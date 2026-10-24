namespace Auth.Api.Hosting;

/// <summary>Startup checks that refuse an insecure configuration instead of running with it.</summary>
internal static class HostingGuards
{
    /// <summary>
    /// Host filtering only protects if AllowedHosts lists real host names. Outside Development an empty value or "*"
    /// stops the app at startup (set AllowedHosts, e.g. through the AllowedHosts environment variable).
    /// </summary>
    public static void EnsureAllowedHostsRestricted(IConfiguration configuration, IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            return;
        }

        string[] hosts = (configuration["AllowedHosts"] ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (hosts.Length == 0 || hosts.Contains("*", StringComparer.Ordinal))
        {
            throw new InvalidOperationException("AllowedHosts must list the public host names outside Development; it is empty or '*'.");
        }
    }

    /// <summary>
    /// Outside Development: BrowserProtection:AllowMissingOrigin (the non-browser escape hatch) is refused, and every
    /// BrowserProtection:TrustedOrigins entry must be an exact https origin (http only for loopback hosts).
    /// </summary>
    public static void EnsureBrowserProtectionSafe(IConfiguration configuration, IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            return;
        }

        if (configuration.GetValue<bool>("BrowserProtection:AllowMissingOrigin"))
        {
            throw new InvalidOperationException("BrowserProtection:AllowMissingOrigin is only allowed in Development.");
        }

        Security.BrowserProtectionMiddleware.NormalizeTrusted(
            configuration.GetSection("BrowserProtection:TrustedOrigins").Get<string[]>() ?? [],
            requireHttps: true);
    }
}
