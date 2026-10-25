using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Auth.Services.Tokens;

namespace Auth.Services.Accounts;

/// <summary>
/// The one place a browser session starts for an authenticated user (T21, used by password login and by the MFA
/// verify step): replaces the browser's previous session, resets the lockout, applies the session cap, issues the
/// family with LoginSucceeded (and the factor's own audit row) in the same save, then mints the access token.
/// </summary>
internal interface IBrowserSessionStarter
{
    /// <param name="user">The authenticated user (password, and second factor when enabled, already proven).</param>
    /// <param name="presentedRefreshToken">The browser's refresh cookie, if any: its session is replaced.</param>
    /// <param name="rehashPassword">The plain password when its hash needs upgrading, else null.</param>
    /// <param name="factorAudit">An extra audit row saved with LoginSucceeded (MfaVerified or MfaRecoveryCodeUsed), or null.</param>
    /// <param name="audit">Who is asking.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    Task<SignedIn> StartAsync(User user, string? presentedRefreshToken, string? rehashPassword, AuditEvent? factorAudit, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class BrowserSessionStarter(
    IUserRepository users,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    IPasswordHasher hasher,
    ILockoutService lockout,
    IRefreshTokenService refreshTokens,
    ITokenService tokens,
    ISessionCap sessionCap,
    IAccessProfileBuilder profiles,
    ISessionEndedPublisher sessionsEnded,
    IClock clock) : IBrowserSessionStarter
{
    public async Task<SignedIn> StartAsync(User user, string? presentedRefreshToken, string? rehashPassword, AuditEvent? factorAudit, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(audit);

        // Re-login replaces the browser's previous session instead of leaving it alive with no cookie pointing at it.
        // The same user signing in again keeps their application sessions (deliberately silent); ANOTHER user taking
        // over this browser is a sign-out of the previous one, so their application sessions end too.
        if (await refreshTokens.FindSessionAsync(presentedRefreshToken, cancellationToken) is RefreshSession previous)
        {
            if (previous.UserId != user.Id && previous.ClientApplicationId is null)
            {
                await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.Browser, SessionEndCause.Logout, previous.UserId, previous.FamilyId), audit, cancellationToken);
            }

            await refreshTokens.RevokeFamilyForUserAsync(previous.FamilyId, previous.UserId, RefreshTokenRevokedReason.Logout, cancellationToken);
        }

        // May clear the change tracker on a retry, so nothing is staged before it, and the user is read again after it.
        await lockout.ResetAsync(user.Id, cancellationToken);
        await sessionCap.MakeRoomAsync(user.Id, null, audit, stageAudit: false, cancellationToken);
        string? newHash = rehashPassword is null ? null : await hasher.HashAsync(rehashPassword, cancellationToken);
        RefreshContext refreshContext = new(audit.IpAddress ?? string.Empty, audit.UserAgent ?? string.Empty);

        IssuedRefreshToken refresh;
        try
        {
            refresh = await IssueWithAuditAsync(user.Id, await users.GetByIdAsync(user.Id, cancellationToken), newHash, factorAudit, refreshContext, audit, cancellationToken);
        }
        catch (ConcurrencyConflictException)
        {
            // The user row changed meanwhile (e.g. a concurrent failed attempt). Skip the optional user updates
            // (last login, rehash) and start the session anyway.
            unitOfWork.ClearChanges();
            refresh = await IssueWithAuditAsync(user.Id, null, null, factorAudit, refreshContext, audit, cancellationToken);
        }

        UserProfileResponse profile = await profiles.BuildProfileAsync(user, null, cancellationToken);
        AccessToken access = await tokens.CreateAccessTokenAsync(profiles.TokenRequest(user, profile, null, refresh.FamilyId), cancellationToken);
        return new SignedIn(access, refresh, profile);
    }

    /// <summary>
    /// Stages the LoginSucceeded row (and the factor's row; for a tracked user, last login and a rehash) and saves them in
    /// the same save that creates the new refresh family.
    /// </summary>
    private async Task<IssuedRefreshToken> IssueWithAuditAsync(
        Guid userId, User? tracked, string? newHash, AuditEvent? factorAudit, RefreshContext refreshContext, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        if (tracked is not null)
        {
            tracked.LastLoginUtc = now;
            if (newHash is not null)
            {
                tracked.PasswordHash = newHash;
                tracked.UpdatedUtc = now;
            }
        }

        if (factorAudit is not null)
        {
            await audits.StageAsync(factorAudit, audit, cancellationToken);
        }

        await audits.StageAsync(AuditEvents.LoginSucceeded(userId), audit, cancellationToken);
        return await refreshTokens.IssueAsync(userId, null, refreshContext, cancellationToken);
    }
}
