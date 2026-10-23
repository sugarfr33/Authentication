namespace Auth.Entities;

/// <summary>Allowed values of <see cref="RefreshToken.RevokedReason"/>.</summary>
public static class RefreshTokenRevokedReason
{
    public const string Rotated = "Rotated";
    public const string Reuse = "Reuse";
    public const string Logout = "Logout";
    public const string LogoutAll = "LogoutAll";
    public const string PasswordChange = "PasswordChange";
    public const string Admin = "Admin";
}
