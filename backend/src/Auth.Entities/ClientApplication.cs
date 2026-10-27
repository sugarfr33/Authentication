namespace Auth.Entities;

/// <summary>An application that relies on central auth. Table <c>auth.ClientApplication</c>.</summary>
public class ClientApplication
{
    public Guid Id { get; set; }

    public string ClientId { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    /// <summary>JSON array of allowed CORS origins.</summary>
    public string AllowedOrigins { get; set; } = "[]";

    /// <summary>JSON array of redirect URIs, matched exactly.</summary>
    public string RedirectUris { get; set; } = "[]";

    /// <summary>JSON array of post-logout redirect URIs, matched exactly.</summary>
    public string PostLogoutRedirectUris { get; set; } = "[]";

    /// <summary>
    /// T30: when true, only users holding at least one of this application's own roles may sign in to it (authorize,
    /// code exchange and refresh). Global roles, Admin included, do not count. Default false.
    /// </summary>
    public bool RequireRole { get; set; }


    public bool IsActive { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime UpdatedUtc { get; set; }
}
