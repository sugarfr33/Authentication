namespace Auth.Contracts.Requests;

/// <summary>POST /api/v1/admin/users/{id}/roles: the role to give (global or application-scoped).</summary>
public sealed record AdminRoleAssignmentRequest(Guid RoleId);

/// <summary>POST /api/v1/admin/roles/{id}/permissions: the permission to grant.</summary>
public sealed record AdminPermissionGrantRequest(Guid PermissionId);

/// <summary>
/// POST /api/v1/admin/apps/{appId}/roles (T30): a new role of the application. <c>Name</c>: 1 to 64 ASCII letters,
/// digits, '.', '_' or '-' (it becomes the claim app:{clientId}:{name}); unique per application, ignoring case.
/// <c>Description</c>: optional, at most 256 characters.
/// </summary>
public sealed record ApplicationRoleRequest(string? Name, string? Description);
