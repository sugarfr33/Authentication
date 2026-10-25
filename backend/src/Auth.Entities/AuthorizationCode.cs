namespace Auth.Entities;

/// <summary>
/// A one-time OAuth authorization code (T19), stored only as its SHA-256 hash, valid 60 seconds, single use. Bound to
/// the user, the client application, the exact redirect URI and the PKCE S256 challenge. Table <c>auth.AuthorizationCode</c>.
/// </summary>
public class AuthorizationCode
{
    public Guid Id { get; set; }

    public byte[] CodeHash { get; set; } = [];

    public Guid UserId { get; set; }

    public Guid ClientApplicationId { get; set; }

    /// <summary>The redirect URI of the request, exactly as registered; the exchange must present the same string.</summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>BASE64URL(SHA-256(code_verifier)), 43 to 128 characters.</summary>
    public string CodeChallenge { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; }

    public DateTime ExpiresUtc { get; set; }

    /// <summary>Set by the first redemption attempt (successful or not): a code is never accepted twice.</summary>
    public DateTime? UsedUtc { get; set; }

    /// <summary>The refresh family (session) started from this code, so a replay can revoke it.</summary>
    public Guid? FamilyId { get; set; }

    public User User { get; set; } = null!;

    public ClientApplication ClientApplication { get; set; } = null!;
}
