namespace Auth.Services.Mfa;

/// <summary>
/// Configuration section <c>Mfa</c> (T21, docs/mfa-totp.md). The keys themselves are secrets read through ISecretStore:
/// <c>MfaEncryptionKey-{id}</c> for each id in <see cref="KeyIds"/> (base64 of 32 bytes) and <c>MfaRecoveryPepper</c>
/// (base64 of 32 bytes, not rotated).
/// </summary>
public sealed class MfaOptions
{
    public const string SectionName = "Mfa";

    /// <summary>Off by default. Off: no MFA endpoint exists, and users who have MFA cannot sign in (fail closed).</summary>
    public bool Enabled { get; set; }

    /// <summary>The key that encrypts new secret blobs; must be listed in <see cref="KeyIds"/>.</summary>
    public string ActiveKeyId { get; set; } = string.Empty;

    /// <summary>Every key id that may still decrypt a blob (the active one and older ones during a rotation).</summary>
    public IList<string> KeyIds { get; } = [];

    /// <summary>The issuer label shown in authenticator apps.</summary>
    public string Issuer { get; set; } = "CentralAuth";

    /// <summary>How long a login challenge (password proven, second factor pending) is valid.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public MfaOptions Validated()
    {
        if (!Enabled)
        {
            return this;
        }

        if (string.IsNullOrWhiteSpace(ActiveKeyId) || !KeyIds.Contains(ActiveKeyId, StringComparer.Ordinal)
            || KeyIds.Any(id => id.Length is 0 or > 16 || !id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')))
        {
            throw new InvalidOperationException("Mfa:ActiveKeyId must be one of Mfa:KeyIds (1 to 16 letters, digits or hyphens each).");
        }

        if (string.IsNullOrWhiteSpace(Issuer) || Issuer.Length > 64 || Issuer.Contains(':', StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Mfa:Issuer must be 1 to 64 characters without ':'.");
        }

        if (ChallengeLifetime < TimeSpan.FromMinutes(1) || ChallengeLifetime > TimeSpan.FromMinutes(15))
        {
            throw new InvalidOperationException("Mfa:ChallengeLifetime must be between 00:01:00 and 00:15:00.");
        }

        return this;
    }
}
