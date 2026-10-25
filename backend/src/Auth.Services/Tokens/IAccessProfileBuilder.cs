using Auth.Contracts.Responses;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.ClientApplications;

namespace Auth.Services.Tokens;

/// <summary>
/// The one place that turns a user into a profile and an access-token request, for browser sessions
/// (<c>application</c> null: default audience, global roles) and client-application sessions (the application's
/// audience and client_id, global roles plus its own roles prefixed <c>app:{clientId}:{name}</c>). Global role names
/// reserved for application roles (starting with <c>app:</c>) are always dropped.
/// </summary>
internal interface IAccessProfileBuilder
{
    Task<UserProfileResponse> BuildProfileAsync(User user, ClientApplication? application, CancellationToken cancellationToken);

    /// <summary>The access-token request for the profile, with sid = <paramref name="sessionId"/> (the refresh family).</summary>
    AccessTokenRequest TokenRequest(User user, UserProfileResponse profile, ClientApplication? application, Guid sessionId);
}

internal sealed class AccessProfileBuilder(IRoleRepository roles, TokenOptions tokenOptions) : IAccessProfileBuilder
{
    public async Task<UserProfileResponse> BuildProfileAsync(User user, ClientApplication? application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        IReadOnlyList<Role> userRoles = await roles.GetForUserAsync(user.Id, application?.Id, cancellationToken);
        IReadOnlyList<string> permissions = await roles.GetPermissionCodesForUserAsync(user.Id, application?.Id, cancellationToken);

        // A global role may never look like an application role (names starting with app: are reserved).
        IEnumerable<string> roleClaims = userRoles
            .Where(r => r.ClientApplicationId is not null || !RoleNames.IsReservedForApplications(r.Name))
            .Select(r => r.ClientApplicationId is null || application is null ? r.Name : RoleNames.AppRole(application.ClientId, r.Name));
        return new UserProfileResponse(
            user.Id,
            user.Email,
            user.EmailVerified,
            user.DisplayName,
            user.MfaEnabled,
            [.. roleClaims.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)],
            [.. permissions.Order(StringComparer.Ordinal)]);
    }

    public AccessTokenRequest TokenRequest(User user, UserProfileResponse profile, ClientApplication? application, Guid sessionId)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(profile);
        return new AccessTokenRequest(
            user.Id,
            user.Email,
            user.DisplayName,
            profile.Roles,
            profile.Permissions,
            application?.Audience ?? tokenOptions.DefaultAudience,
            application?.ClientId,
            sessionId);
    }
}
