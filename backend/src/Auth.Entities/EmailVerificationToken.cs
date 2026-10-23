namespace Auth.Entities;

/// <summary>Single-use email verification token, stored as a SHA-256 hash and valid 24 h. Table <c>auth.EmailVerificationToken</c>.</summary>
public class EmailVerificationToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public byte[] TokenHash { get; set; } = [];

    public DateTime CreatedUtc { get; set; }

    public DateTime ExpiresUtc { get; set; }

    public DateTime? UsedUtc { get; set; }

    public User User { get; set; } = null!;
}
