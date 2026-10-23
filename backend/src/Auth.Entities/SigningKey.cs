namespace Auth.Entities;

/// <summary>
/// A JWT signing key. Only the public JWK and a reference to the private key in the secret store are kept here,
/// never private key material. Table <c>auth.SigningKey</c>.
/// </summary>
public class SigningKey
{
    public Guid Id { get; set; }

    public string Kid { get; set; } = string.Empty;

    /// <summary>One of <see cref="SigningKeyAlgorithm"/>.</summary>
    public string Algorithm { get; set; } = string.Empty;

    public string PublicKeyJwk { get; set; } = string.Empty;

    public string PrivateKeyReference { get; set; } = string.Empty;

    /// <summary>One of <see cref="SigningKeyStatus"/>.</summary>
    public string Status { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; }

    public DateTime? ActivatedUtc { get; set; }

    public DateTime? RetireAfterUtc { get; set; }
}
