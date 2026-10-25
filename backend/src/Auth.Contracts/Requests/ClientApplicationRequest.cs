namespace Auth.Contracts.Requests;

/// <summary>
/// Create or update a client application. Lists are matched exactly: origins (<c>scheme://host[:port]</c>), redirect
/// and post-logout redirect URIs. The client id cannot change after creation.
/// </summary>
public sealed record ClientApplicationRequest(
    string ClientId,
    string Name,
    string Audience,
    IReadOnlyList<string> AllowedOrigins,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);
