using Microsoft.Extensions.Configuration;

namespace Auth.Services.Common;

/// <summary>
/// Development secret store over <see cref="IConfiguration"/>, which the host feeds from User Secrets and environment
/// variables. Lookup order for a secret named <c>n</c>:
/// <list type="number">
/// <item><c>Secrets:n</c>, the secret text itself (environment variable <c>Secrets__n</c>);</item>
/// <item><c>SecretFiles:n</c>, a path to a file (e.g. a PEM) whose content is the secret.</item>
/// </list>
/// Nothing is read from source code or the database.
/// </summary>
internal sealed class ConfigurationSecretStore(IConfiguration configuration) : ISecretStore
{
    public async Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (name.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException("Secret names cannot contain ':'.", nameof(name));
        }

        string? inline = configuration["Secrets:" + name];
        if (!string.IsNullOrEmpty(inline))
        {
            return inline;
        }

        string? path = configuration["SecretFiles:" + name];
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        if (!File.Exists(path))
        {
            // The path is configuration, not secret, but keep the message generic anyway.
            throw new InvalidOperationException("The file configured for secret '" + name + "' does not exist.");
        }

        return await File.ReadAllTextAsync(path, cancellationToken);
    }
}
