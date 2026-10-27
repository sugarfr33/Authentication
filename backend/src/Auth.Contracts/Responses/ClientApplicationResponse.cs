namespace Auth.Contracts.Responses;

/// <summary>A registered client application.</summary>
public sealed record ClientApplicationResponse(
    Guid Id,
    string ClientId,
    string Name,
    string Audience,
    IReadOnlyList<string> AllowedOrigins,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    bool IsActive,
    bool RequireRole);
