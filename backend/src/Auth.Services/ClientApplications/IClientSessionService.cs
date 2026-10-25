using Auth.Contracts;
using Auth.Contracts.Responses;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Tokens;

namespace Auth.Services.ClientApplications;

/// <summary>
/// Sessions at registered client applications: a refresh family tied to the application and an access token with
/// <c>aud</c> = the application's audience and <c>client_id</c> = its client id, carrying global roles plus that
/// application's roles, the latter prefixed <c>app:{clientId}:{name}</c> so they can never be mistaken for a global role
/// of the same name. An inactive or unknown application gets nothing.
/// </summary>
public interface IClientSessionService
{
    /// <summary>
    /// Starts a session for <paramref name="userId"/>. It trusts the user id it is given: call it ONLY after a verified
    /// authorization-code exchange bound to the same user and client (the OAuth service is its only caller).
    /// </summary>
    /// <returns>InvalidClient for an unknown or inactive application; Forbidden for an inactive or unverified user.</returns>
    Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, RefreshContext context, CancellationToken cancellationToken);

    /// <summary>
    /// The refresh grant for application families: the family must belong to <paramref name="clientId"/>, which must be
    /// active, and the user must be active. Rotation with reuse detection, as for browser sessions; audited.
    /// </summary>
    /// <returns>InvalidClient for an unknown or inactive application; InvalidGrant for any token problem.</returns>
    Task<Result<SignedIn>> RefreshAsync(string? refreshToken, string clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class ClientSessionService(
    IClientApplicationRepository applications,
    IUserRepository users,
    IRoleRepository roles,
    IRefreshTokenService refreshTokens,
    ITokenService tokens,
    IAuditService audits) : IClientSessionService
{
    public async Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, RefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ClientApplication? application = await ActiveApplicationAsync(clientId, cancellationToken);
        if (application is null)
        {
            return Result.Failure<SignedIn>(AuthError.InvalidClient);
        }

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            return Result.Failure<SignedIn>(AuthError.Forbidden);
        }

        IssuedRefreshToken refresh;
        try
        {
            refresh = await refreshTokens.IssueAsync(user.Id, application.Id, context, cancellationToken);
        }
        catch (InactiveClientApplicationException)
        {
            // Deactivated between the check above and the issue (T18 audit L4).
            return Result.Failure<SignedIn>(AuthError.InvalidClient);
        }

        return Result.Success(await MintAsync(user, application, refresh, cancellationToken));
    }

    public async Task<Result<SignedIn>> RefreshAsync(string? refreshToken, string clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(audit);
        ClientApplication? application = await ActiveApplicationAsync(clientId, cancellationToken);
        if (application is null)
        {
            return Result.Failure<SignedIn>(AuthError.InvalidClient);
        }

        // Browser-session families (no application) and other applications' families are refused here, just as the
        // cookie refresh refuses application families.
        RefreshSession? session = await refreshTokens.FindSessionAsync(refreshToken, cancellationToken);
        if (session is null || session.ClientApplicationId != application.Id)
        {
            await audits.TryWriteAsync(AuditEvents.AuthorizationCodeRejected(session?.UserId, application.Id, session is null ? "unknown_or_expired" : "client_mismatch"), audit, cancellationToken);
            return Result.Failure<SignedIn>(AuthError.InvalidGrant);
        }

        // Stage nothing before the rotation: it may clear the change tracker on its retry.
        RotationResult rotation = await refreshTokens.RotateAsync(refreshToken!, context, cancellationToken);
        switch (rotation.Status)
        {
            case RotationStatus.Rotated when rotation.Token is IssuedRefreshToken token:
                User? user = await users.GetByIdAsync(token.UserId, cancellationToken);
                if (user is not { IsActive: true, EmailVerified: true })
                {
                    await refreshTokens.RevokeFamilyForUserAsync(token.FamilyId, token.UserId, Entities.RefreshTokenRevokedReason.Admin, cancellationToken);
                    return Result.Failure<SignedIn>(AuthError.InvalidGrant);
                }

                await audits.TryWriteAsync(AuditEvents.TokenRefreshed(user.Id), audit, cancellationToken);
                return Result.Success(await MintAsync(user, application, token, cancellationToken));

            case RotationStatus.ReuseDetected when rotation.Reuse is TokenReuseDetected reuse:
                await audits.TryWriteAsync(
                    reuse.RevokedCount > 0 ? AuditEvents.TokenReuse(reuse.UserId, reuse.RevokedCount) : AuditEvents.RefreshRejected(reuse.UserId, "ended_session_replayed"),
                    audit,
                    cancellationToken);
                return Result.Failure<SignedIn>(AuthError.InvalidGrant);

            default:
                return Result.Failure<SignedIn>(AuthError.InvalidGrant);
        }
    }

    /// <summary>The claim value of an application-scoped role.</summary>
    internal static string AppRole(string clientId, string roleName) => "app:" + clientId + ":" + roleName;

    private async Task<ClientApplication?> ActiveApplicationAsync(string? clientId, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(clientId)
            ? null
            : await applications.GetByClientIdAsync(clientId, cancellationToken) is { IsActive: true } application ? application : null;

    private async Task<SignedIn> MintAsync(User user, ClientApplication application, IssuedRefreshToken refresh, CancellationToken cancellationToken)
    {
        IReadOnlyList<Role> userRoles = await roles.GetForUserAsync(user.Id, application.Id, cancellationToken);
        IReadOnlyList<string> permissions = await roles.GetPermissionCodesForUserAsync(user.Id, application.Id, cancellationToken);

        // A global role may never look like an application role (names starting with app: are reserved).
        IEnumerable<string> roleClaims = userRoles
            .Where(r => r.ClientApplicationId is not null || !RoleNames.IsReservedForApplications(r.Name))
            .Select(r => r.ClientApplicationId is null ? r.Name : AppRole(application.ClientId, r.Name));
        UserProfileResponse profile = new(
            user.Id,
            user.Email,
            user.EmailVerified,
            user.DisplayName,
            user.MfaEnabled,
            [.. roleClaims.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)],
            [.. permissions.Order(StringComparer.Ordinal)]);

        AccessToken access = await tokens.CreateAccessTokenAsync(
            new AccessTokenRequest(user.Id, user.Email, user.DisplayName, profile.Roles, profile.Permissions, application.Audience, application.ClientId, refresh.FamilyId),
            cancellationToken);
        return new SignedIn(access, refresh, profile);
    }
}

/// <summary>Rules for role names (T18 review: global roles must never look like application roles).</summary>
public static class RoleNames
{
    public const string ApplicationPrefix = "app:";

    /// <summary>
    /// True for names a GLOBAL role may not have: they start with <c>app:</c>, the claim prefix of application roles.
    /// Any future role-creation code must refuse such global names; app tokens drop them defensively.
    /// </summary>
    public static bool IsReservedForApplications(string name) =>
        name.TrimStart().StartsWith(ApplicationPrefix, StringComparison.OrdinalIgnoreCase);
}
