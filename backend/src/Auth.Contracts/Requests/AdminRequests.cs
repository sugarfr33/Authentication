namespace Auth.Contracts.Requests;

/// <summary>POST /api/v1/admin/users/{id}/roles: the role to give (global or application-scoped).</summary>
public sealed record AdminRoleAssignmentRequest(Guid RoleId);

/// <summary>POST /api/v1/admin/roles/{id}/permissions: the permission to grant.</summary>
public sealed record AdminPermissionGrantRequest(Guid PermissionId);
