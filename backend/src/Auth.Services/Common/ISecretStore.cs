namespace Auth.Services.Common;

/// <summary>
/// Reads secrets by name, such as the private signing key named by <c>SigningKey.PrivateKeyReference</c>.
/// Dev: configuration (User Secrets, environment variables) or a PEM file path. Prod: a key vault implementation.
/// Secret values must never be logged or put in exception messages.
/// </summary>
public interface ISecretStore
{
    /// <summary>Returns the secret text, or null when no secret has that name.</summary>
    Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken);
}
