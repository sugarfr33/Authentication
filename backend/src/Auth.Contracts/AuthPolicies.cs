namespace Auth.Contracts;

/// <summary>Permission codes, stored in <c>auth.Permission.Code</c> and carried by access tokens as <c>perm</c> claims.</summary>
public static class AuthPermissions
{
    public const string UsersRead = "users.read";
    public const string UsersWrite = "users.write";
    public const string RolesManage = "roles.manage";
    public const string SessionsManage = "sessions.manage";
    public const string AuditRead = "audit.read";
    public const string AppsManage = "apps.manage";

    /// <summary>Every permission the seeder creates; each one also has an authorization policy of the same name.</summary>
    public static readonly IReadOnlyList<string> All = [UsersRead, UsersWrite, RolesManage, SessionsManage, AuditRead, AppsManage];
}

/// <summary>System roles created by the seeder (global, not tied to a client application).</summary>
public static class AuthRoles
{
    /// <summary>Holds every permission in <see cref="AuthPermissions.All"/>.</summary>
    public const string Admin = "Admin";

    /// <summary>Default role of every verified account; no administrative permission.</summary>
    public const string User = "User";
}

/// <summary>
/// Authorization policy names. Each permission policy has the permission code as its name and requires a <c>perm</c>
/// claim with that code; role policies require a <c>role</c> claim.
/// </summary>
public static class AuthPolicies
{
    public const string UsersRead = AuthPermissions.UsersRead;
    public const string UsersWrite = AuthPermissions.UsersWrite;
    public const string RolesManage = AuthPermissions.RolesManage;
    public const string SessionsManage = AuthPermissions.SessionsManage;
    public const string AuditRead = AuthPermissions.AuditRead;
    public const string AppsManage = AuthPermissions.AppsManage;

    /// <summary>Requires the Admin role.</summary>
    public const string AdminRole = "role:" + AuthRoles.Admin;
}
