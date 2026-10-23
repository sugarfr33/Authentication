namespace Auth.Contracts;

/// <summary>JWT claim names issued by central auth and read by client applications.</summary>
public static class AuthClaimTypes
{
    public const string Subject = "sub";
    public const string Email = "email";
    public const string Name = "name";
    public const string Role = "role";
    public const string Permission = "perm";

    /// <summary>Refresh-token family (session) id.</summary>
    public const string SessionId = "sid";

    public const string ClientId = "client_id";
}
