namespace Auth.Entities;

/// <summary>Single-use MFA recovery code, stored as a SHA-256 hash. Table <c>auth.MfaRecoveryCode</c>.</summary>
public class MfaRecoveryCode
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public byte[] CodeHash { get; set; } = [];

    public DateTime CreatedUtc { get; set; }

    public DateTime? UsedUtc { get; set; }

    public User User { get; set; } = null!;
}
