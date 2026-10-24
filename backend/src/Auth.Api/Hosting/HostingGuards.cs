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
}
