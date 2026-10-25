using Auth.Contracts;
using Auth.Contracts.Responses;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Common;
using Auth.Services.Tokens;

namespace Auth.Services.ClientApplications;

/// <summary>
/// Sessions at registered client applications: a refresh family tied to the application and an access token with
/// <c>aud</c> = the application's audience and <c>client_id</c> = its client id, carrying global roles plus that
/// application's roles, the latter prefixed <c>app:{clientId}:{name}</c> (IAccessProfileBuilder) so they can never be
/// mistaken for a global role of the same name. An inactive or unknown application gets nothing. Starting a session
/// applies the per-user session cap (ISessionCap), counted across browser and application sessions; refreshing uses the
/// same pipeline as browser sessions (ISessionRefresher).
/// </summary>
public interface IClientSessionService
{
    /// <summary>
    /// Starts a session for <paramref name="userId"/> as family <paramref name="familyId"/> (chosen by the caller, which
    /// recorded it on the authorization code). It trusts the user id it is given: call it ONLY after a verified
    /// authorization-code exchange bound to the same user and client (the OAuth service is its only caller; an
    /// architecture test checks that). Makes no commit of its own beyond the family's save, so the caller's transaction
    /// covers it.
    /// </summary>
    /// <returns>InvalidClient for an unknown or inactive application; Forbidden for an inactive or unverified user.</returns>
    Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, Guid familyId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// The refresh grant for application families: the family must belong to <paramref name="clientId"/>, which must be
    /// active, and the user must be active. Rotation with reuse detection and the post-rotation checks, as for browser
    /// sessions; audited (TokenRefreshed, TokenReuse, RefreshRejected with the application).
    /// </summary>
    /// <returns>InvalidClient for an unknown or inactive application; InvalidGrant for any token problem.</returns>
    Task<Result<SignedIn>> RefreshAsync(string? refreshToken, string clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class ClientSessionService(
    IClientApplicationRepository applications,
    IUserRepository users,
    IRefreshTokenService refreshTokens,
    ISessionCap sessionCap,
    ISessionRefresher refresher,
    IAccessProfileBuilder profiles,
    ITokenService tokens) : IClientSessionService
{
    public async Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, Guid familyId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(audit);
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

        // Staged: saved with the new family, inside the exchange's transaction.
        await sessionCap.MakeRoomAsync(user.Id, application.Id, audit, stageAudit: true, cancellationToken);
        IssuedRefreshToken refresh;
        try
        {
            refresh = await refreshTokens.IssueAsync(user.Id, application.Id, familyId, context, cancellationToken);
        }
        catch (InactiveClientApplicationException)
        {
            // Deactivated between the check above and the issue (T18 audit L4).
            return Result.Failure<SignedIn>(AuthError.InvalidClient);
        }

        UserProfileResponse profile = await profiles.BuildProfileAsync(user, application, cancellationToken);
        AccessToken access = await tokens.CreateAccessTokenAsync(profiles.TokenRequest(user, profile, application, refresh.FamilyId), cancellationToken);
        return Result.Success(new SignedIn(access, refresh, profile));
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

        RefreshOutcome outcome = await refresher.RefreshAsync(refreshToken, application, context, audit, cancellationToken);
        return outcome.Session is SignedIn session ? Result.Success(session) : Result.Failure<SignedIn>(AuthError.InvalidGrant);
    }

    private async Task<ClientApplication?> ActiveApplicationAsync(string? clientId, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(clientId)
            ? null
            : await applications.GetByClientIdAsync(clientId, cancellationToken) is { IsActive: true } application ? application : null;
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

    /// <summary>The claim value of an application-scoped role: <c>app:{clientId}:{name}</c>.</summary>
    public static string AppRole(string clientId, string roleName) => ApplicationPrefix + clientId + ":" + roleName;
}
