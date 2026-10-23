namespace Auth.Entities;

/// <summary>Grant of a permission to a role. Table <c>auth.RolePermission</c>, key (RoleId, PermissionId).</summary>
public class RolePermission
{
    public Guid RoleId { get; set; }

    public Guid PermissionId { get; set; }

    public Role Role { get; set; } = null!;

    public Permission Permission { get; set; } = null!;
}
