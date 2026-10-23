namespace Auth.Entities;

/// <summary>
/// One rotation of a refresh token. A session is one <see cref="FamilyId"/>. Only the SHA-256 hash is stored.
/// Table <c>auth.RefreshToken</c>.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public Guid? ClientApplicationId { get; set; }

    public Guid FamilyId { get; set; }

    public byte[] TokenHash { get; set; } = [];

    public DateTime CreatedUtc { get; set; }

    public DateTime ExpiresUtc { get; set; }

    public DateTime? RevokedUtc { get; set; }

    /// <summary>One of <see cref="RefreshTokenRevokedReason"/>.</summary>
    public string? RevokedReason { get; set; }

    public Guid? ReplacedByTokenId { get; set; }

    public string IpAddress { get; set; } = string.Empty;

    public string UserAgent { get; set; } = string.Empty;

    public byte[] RowVersion { get; set; } = [];

    public User User { get; set; } = null!;

    public ClientApplication? ClientApplication { get; set; }

    public RefreshToken? ReplacedByToken { get; set; }
}
