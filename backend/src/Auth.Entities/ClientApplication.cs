namespace Auth.Entities;

/// <summary>An application that relies on central auth. Table <c>auth.ClientApplication</c>.</summary>
public class ClientApplication
{
    public Guid Id { get; set; }

    public string ClientId { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    /// <summary>JSON array of allowed CORS origins.</summary>
    public string AllowedOrigin { get; set; } = "[]";

    /// <summary>JSON array of redirect URIs, matched exactly.</summary>
    public string RedirectUri { get; set; } = "[]";

    /// <summary>JSON array of post-logout redirect URIs, matched exactly.</summary>
    public string PostLogoutRedirectUri { get; set; } = "[]";

    public bool RequirePkce { get; set; } = true;

    public bool IsActive { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime UpdatedUtc { get; set; }
}
