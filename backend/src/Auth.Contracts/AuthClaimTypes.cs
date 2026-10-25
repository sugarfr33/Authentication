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

/// <summary>JWT header <c>typ</c> values issued by central auth; resource servers accept only these (T22).</summary>
public static class AuthTokenTypes
{
    /// <summary>RFC 9068 access token. Validation accepts only this, so ID tokens or other JWTs cannot be replayed as access tokens.</summary>
    public const string AccessToken = "at+jwt";
}
