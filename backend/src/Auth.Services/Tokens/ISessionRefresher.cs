using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Audit;
using Auth.Services.Common;

namespace Auth.Services.Tokens;

/// <summary>
/// The one refresh pipeline, shared by browser sessions (cookie refresh) and client-application sessions (the OAuth
/// refresh grant), so both get the same hardening:
/// <list type="number">
/// <item>Read-only preparation BEFORE rotating (session, its owner and application, user, profile, the new access
/// token): a failure there leaves the presented token untouched and the client can simply retry.</item>
/// <item>The rotation (its own transaction, one winner of a race, reuse revokes the family).</item>
/// <item>After the commit, the user (password change, disabled) and the application are read again; a successor that
/// cannot be completed is revoked, so no orphan stays live.</item>
/// <item>Audit is best effort: TokenRefreshed, TokenReuse or RefreshRejected.</item>
/// </list>
/// </summary>
internal interface ISessionRefresher
{
    /// <param name="presentedRefreshToken">The raw refresh token.</param>
    /// <param name="application">The client application the family must belong to, or null for a browser session.
    /// A family of another application, or of the browser, is refused either way.</param>
    /// <param name="context">Where the refresh comes from (stored on the successor).</param>
    /// <param name="audit">Who is asking.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    Task<RefreshOutcome> RefreshAsync(string? presentedRefreshToken, ClientApplication? application, RefreshContext context, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class SessionRefresher(
    IUserRepository users,
    IClientApplicationRepository applications,
    IRefreshTokenService refreshTokens,
    IAccessProfileBuilder profiles,
    ITokenService tokens,
    IAuditService audits,
    IUnitOfWork unitOfWork) : ISessionRefresher
{
    public async Task<RefreshOutcome> RefreshAsync(string? presentedRefreshToken, ClientApplication? application, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(audit);

        // 1. Read-only preparation.
        RefreshSession? session = await refreshTokens.FindSessionAsync(presentedRefreshToken, cancellationToken);
        if (session is null)
        {
            return new RefreshOutcome(RotationStatus.Invalid, null);
        }

        if (session.ClientApplicationId != application?.Id)
        {
            // A family keeps its own audience: browser families are never refreshed by the OAuth grant, application
            // families never by the cookie refresh, and one application never refreshes another's.
            if (application is not null)
            {
                await audits.TryWriteAsync(AuditEvents.RefreshRejected(session.UserId, "client_mismatch", application.Id), audit, cancellationToken);
            }

            return new RefreshOutcome(RotationStatus.Invalid, null);
        }

        User? user = await users.GetByIdAsync(session.UserId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            await refreshTokens.RevokeFamilyForUserAsync(session.FamilyId, session.UserId, RefreshTokenRevokedReason.Admin, cancellationToken);
            return new RefreshOutcome(RotationStatus.Invalid, null);
        }

        Guid stamp = user.SecurityStamp;
        UserProfileResponse profile = await profiles.BuildProfileAsync(user, application, cancellationToken);
        AccessToken access = await tokens.CreateAccessTokenAsync(profiles.TokenRequest(user, profile, application, session.FamilyId), cancellationToken);

        // 2. The rotation (its own transaction; may clear the change tracker on its retry).
        RotationResult rotation = await refreshTokens.RotateAsync(presentedRefreshToken!, context, cancellationToken);

        switch (rotation.Status)
        {
            case RotationStatus.Rotated when rotation.Token is IssuedRefreshToken token:
                // 3. After the commit nothing may fail silently: a session that cannot be completed is revoked, so no
                //    orphaned successor stays live and the client gets a clean refusal instead of a 500.
                string? rejection;
                try
                {
                    rejection = await CheckAfterRotationAsync(token, session, stamp, application, cancellationToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    rejection = "post_rotation_failure";
                }

                if (rejection is not null)
                {
                    await TryRevokeAsync(token.FamilyId, token.UserId, cancellationToken);
                    await audits.TryWriteAsync(AuditEvents.RefreshRejected(token.UserId, rejection, application?.Id), audit, cancellationToken);
                    return new RefreshOutcome(RotationStatus.Invalid, null);
                }

                await audits.TryWriteAsync(AuditEvents.TokenRefreshed(user.Id), audit, cancellationToken);
                return new RefreshOutcome(RotationStatus.Rotated, new SignedIn(access, token, profile));

            case RotationStatus.ReuseDetected when rotation.Reuse is TokenReuseDetected reuse:
                // Only a replay that actually revoked a live family is a theft signal. A token of a session that had
                // already ended (logout, password change, revoked session) is just rejected.
                await audits.TryWriteAsync(
                    reuse.RevokedCount > 0 ? AuditEvents.TokenReuse(reuse.UserId, reuse.RevokedCount) : AuditEvents.RefreshRejected(reuse.UserId, "ended_session_replayed", application?.Id),
                    audit,
                    cancellationToken);
                return new RefreshOutcome(RotationStatus.ReuseDetected, null);

            default:
                return new RefreshOutcome(rotation.Status, null);
        }
    }

    /// <summary>
    /// Re-reads the user and the application after the rotation (not the tracked copies): if the password changed (new
    /// SecurityStamp), the account was disabled or the application deactivated while refreshing, the successor must not
    /// live. Returns a rejection reason or null.
    /// </summary>
    private async Task<string?> CheckAfterRotationAsync(IssuedRefreshToken token, RefreshSession session, Guid stamp, ClientApplication? application, CancellationToken cancellationToken)
    {
        if (token.FamilyId != session.FamilyId || token.UserId != session.UserId || token.ClientApplicationId != application?.Id)
        {
            return "session_mismatch";
        }

        unitOfWork.ClearChanges();
        User? current = await users.GetByIdAsync(token.UserId, cancellationToken);
        string? userProblem = current switch
        {
            null => "unknown_user",
            { IsActive: false } or { EmailVerified: false } => "account_disabled",
            _ when current.SecurityStamp != stamp => "credentials_changed",
            _ => null,
        };
        if (userProblem is not null || application is null)
        {
            return userProblem;
        }

        return await applications.GetByIdAsync(application.Id, cancellationToken) is { IsActive: true } ? null : "inactive_client";
    }

    private async Task TryRevokeAsync(Guid familyId, Guid userId, CancellationToken cancellationToken)
    {
        try
        {
            await refreshTokens.RevokeFamilyForUserAsync(familyId, userId, RefreshTokenRevokedReason.Admin, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Best effort: the rotated token was never handed out, so the family is unusable to the client anyway.
        }
    }
}
