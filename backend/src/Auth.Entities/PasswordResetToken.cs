namespace Auth.Entities;

/// <summary>Single-use password reset token, stored as a SHA-256 hash and valid 15 min. Table <c>auth.PasswordResetToken</c>.</summary>
public class PasswordResetToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public byte[] TokenHash { get; set; } = [];

    public DateTime CreatedUtc { get; set; }

    public DateTime ExpiresUtc { get; set; }

    public DateTime? UsedUtc { get; set; }

    public string RequestIp { get; set; } = string.Empty;

    public User User { get; set; } = null!;
}
