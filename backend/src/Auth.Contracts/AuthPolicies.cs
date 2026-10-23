namespace Auth.Contracts;

/// <summary>Authorization policy names; each requires the permission code of the same value.</summary>
public static class AuthPolicies
{
    public const string UsersRead = "users.read";
    public const string UsersWrite = "users.write";
    public const string AppsManage = "apps.manage";
}
