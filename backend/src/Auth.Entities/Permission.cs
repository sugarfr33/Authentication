namespace Auth.Entities;

/// <summary>A permission code such as <c>users.read</c>. Table <c>auth.Permission</c>.</summary>
public class Permission
{
    public Guid Id { get; set; }

    public string Code { get; set; } = string.Empty;

    public string? Description { get; set; }

    public ICollection<RolePermission> RolePermissions { get; } = new List<RolePermission>();
}
