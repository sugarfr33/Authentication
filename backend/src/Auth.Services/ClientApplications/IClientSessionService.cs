using Auth.Contracts;
using Auth.Contracts.Responses;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Tokens;

namespace Auth.Services.ClientApplications;

/// <summary>
/// Starts a session of an already authenticated user at a registered client application: a refresh family tied to the
/// application and an access token with <c>aud</c> = the application's audience and <c>client_id</c> = its client id,
/// carrying global roles plus that application's roles. Used by the OAuth code exchange (T19); there is no HTTP route to
/// it yet. An inactive or unknown application gets nothing.
/// </summary>
public interface IClientSessionService
{
    /// <returns>InvalidClient for an unknown or inactive application; Forbidden for an inactive or unverified user.</returns>
    Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, RefreshContext context, CancellationToken cancellationToken);
}

internal sealed class ClientSessionService(
    IClientApplicationRepository applications,
    IUserRepository users,
    IRoleRepository roles,
    IRefreshTokenService refreshTokens,
    ITokenService tokens) : IClientSessionService
{
    public async Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, RefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ClientApplication? application = string.IsNullOrWhiteSpace(clientId) ? null : await applications.GetByClientIdAsync(clientId, cancellationToken);
        if (application is not { IsActive: true })
        {
            return Result.Failure<SignedIn>(AuthError.InvalidClient);
        }

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            return Result.Failure<SignedIn>(AuthError.Forbidden);
        }

        IReadOnlyList<Role> userRoles = await roles.GetForUserAsync(user.Id, application.Id, cancellationToken);
        IReadOnlyList<string> permissions = await roles.GetPermissionCodesForUserAsync(user.Id, application.Id, cancellationToken);
        UserProfileResponse profile = new(
            user.Id,
            user.Email,
            user.EmailVerified,
            user.DisplayName,
            user.MfaEnabled,
            [.. userRoles.Select(r => r.Name).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)],
            [.. permissions.Order(StringComparer.Ordinal)]);

        IssuedRefreshToken refresh = await refreshTokens.IssueAsync(user.Id, application.Id, context, cancellationToken);
        AccessToken access = await tokens.CreateAccessTokenAsync(
            new AccessTokenRequest(user.Id, user.Email, user.DisplayName, profile.Roles, profile.Permissions, application.Audience, application.ClientId, refresh.FamilyId),
            cancellationToken);
        return Result.Success(new SignedIn(access, refresh, profile));
    }
}
