namespace Auth.Entities;

/// <summary>Assignment of a role to a user. Table <c>auth.UserRole</c>, key (UserId, RoleId).</summary>
public class UserRole
{
    public Guid UserId { get; set; }

    public Guid RoleId { get; set; }

    public DateTime AssignedUtc { get; set; }

    public User User { get; set; } = null!;

    public Role Role { get; set; } = null!;
}
