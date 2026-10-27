namespace Auth.Contracts.Requests;

/// <summary>
/// Create or update a client application. Lists are matched exactly: origins (<c>scheme://host[:port]</c>), redirect
/// and post-logout redirect URIs. The client id cannot change after creation. <c>RequireRole</c> (T30, default false):
/// only users holding one of the application's own roles may sign in to it. A PUT replaces every field, so leaving it
/// out turns it off.
/// </summary>
public sealed record ClientApplicationRequest(
    string ClientId,
    string Name,
    string Audience,
    IReadOnlyList<string> AllowedOrigins,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    bool RequireRole = false);
