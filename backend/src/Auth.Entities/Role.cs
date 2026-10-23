namespace Auth.Entities;

/// <summary>A named set of permissions, global or scoped to one client application. Table <c>auth.Role</c>.</summary>
public class Role
{
    public Guid Id { get; set; }

    /// <summary>Null for a global role.</summary>
    public Guid? ClientApplicationId { get; set; }

    public string Name { get; set; } = string.Empty;

    public string NormalizedName { get; set; } = string.Empty;

    public string? Description { get; set; }

    public bool IsSystem { get; set; }

    public ClientApplication? ClientApplication { get; set; }

    public ICollection<UserRole> UserRoles { get; } = new List<UserRole>();

    public ICollection<RolePermission> RolePermissions { get; } = new List<RolePermission>();
}
