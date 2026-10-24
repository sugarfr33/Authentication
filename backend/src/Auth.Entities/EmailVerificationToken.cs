namespace Auth.Entities;

/// <summary>
/// Single-use email verification token, stored as a SHA-256 hash and valid 24 h. Table <c>auth.EmailVerificationToken</c>.
/// It also carries the password hash and display name of the registration that produced it: they are copied to the
/// User row only when this token is redeemed, so a link activates only its own registration's password.
/// </summary>
public class EmailVerificationToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public byte[] TokenHash { get; set; } = [];

    public DateTime CreatedUtc { get; set; }

    public DateTime ExpiresUtc { get; set; }

    public DateTime? UsedUtc { get; set; }

    /// <summary>Argon2id hash chosen at the registration that produced this link; null for links that set no password.</summary>
    public string? PendingPasswordHash { get; set; }

    /// <summary>Display name chosen at the registration that produced this link.</summary>
    public string? PendingDisplayName { get; set; }

    public User User { get; set; } = null!;
}
