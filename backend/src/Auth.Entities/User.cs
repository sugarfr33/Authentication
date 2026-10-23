namespace Auth.Entities;

/// <summary>A person who can sign in. Table <c>auth.User</c>.</summary>
public class User
{
    public Guid Id { get; set; }

    public string Email { get; set; } = string.Empty;

    public string NormalizedEmail { get; set; } = string.Empty;

    public bool EmailVerified { get; set; }

    public string PasswordHash { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public bool IsActive { get; set; }

    public int FailedLoginCount { get; set; }

    public DateTime? LockoutEndUtc { get; set; }

    /// <summary>Exponential-backoff step reached by consecutive lockouts.</summary>
    public int LockoutLevel { get; set; }

    public bool MfaEnabled { get; set; }

    /// <summary>TOTP secret protected with Data Protection; never the plain secret.</summary>
    public byte[]? MfaSecretEncrypted { get; set; }

    /// <summary>Changes whenever credentials change, which invalidates existing sessions.</summary>
    public Guid SecurityStamp { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime UpdatedUtc { get; set; }

    public DateTime? LastLoginUtc { get; set; }

    public byte[] RowVersion { get; set; } = [];

    public ICollection<UserRole> UserRoles { get; } = new List<UserRole>();
}
