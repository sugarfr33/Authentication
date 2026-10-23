namespace Auth.Entities;

/// <summary>Allowed values of <see cref="SigningKey.Status"/>.</summary>
public static class SigningKeyStatus
{
    public const string Active = "Active";
    public const string Retiring = "Retiring";
    public const string Retired = "Retired";
}
