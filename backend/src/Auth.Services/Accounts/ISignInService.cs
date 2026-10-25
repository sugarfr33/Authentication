using System.Globalization;
using Auth.Contracts;
using Auth.Contracts.Requests;
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

/// <summary>A started session: the tokens go to cookies only, the profile to the response body.</summary>
public sealed record SignedIn(AccessToken AccessToken, IssuedRefreshToken RefreshToken, UserProfileResponse Profile);

/// <summary>Outcome of a refresh: <see cref="Session"/> is set only when the status is Rotated.</summary>
/// <param name="Status">Rotated, Concurrent, ReuseDetected or Invalid.</param>
/// <param name="Session">The new tokens and profile, when rotated.</param>
public sealed record RefreshOutcome(RotationStatus Status, SignedIn? Session);

/// <summary>Email and password sign-in, sign-out and the signed-in profile (T13).</summary>
public interface ISignInService
{
    /// <summary>
    /// Checks the credentials and starts a session (refresh family plus an access token for the default audience).
    /// Unknown email, wrong password, unverified, inactive or locked account all give the one
    /// <see cref="AuthError.GenericInvalidCredentials"/>, after the same work: one Argon2 Verify (a dummy hash when the
    /// account cannot sign in), one lockout round trip and one audit row.
    /// </summary>
    /// <param name="request">Email and password. <see cref="LoginRequest.ClientId"/> is ignored: client sign-in is the OAuth flow.</param>
    /// <param name="presentedRefreshToken">The refresh cookie the browser sent, if any: on success its session is revoked,
    /// so signing in again never leaves the previous session alive.</param>
    /// <param name="audit">Who is asking.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <exception cref="PasswordHashingBusyException">No hashing slot freed up in time (the host answers 503).</exception>
    Task<Result<SignedIn>> LoginAsync(LoginRequest request, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Ends the browser's session, found from either cookie: the <paramref name="accessSessionId"/> (sid) of the signed
    /// access cookie, and the family of the <paramref name="presentedRefreshToken"/>. Each family is revoked only for its
    /// own user. Writes a Logout audit row (without a user id when the account no longer exists). Returns the number of
    /// tokens revoked.
    /// </summary>
    Task<int> LogoutAsync(Guid? accessUserId, Guid? accessSessionId, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Ends every session of the user: revokes all refresh families and writes a LogoutAll audit row.</summary>
    Task<int> LogoutAllAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>The profile of an active user, without secrets; <see cref="AuthError.NotFound"/> for a missing or inactive one.</summary>
    Task<Result<UserProfileResponse>> GetProfileAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// Rotates the presented refresh token (T08 rules: one winner of a race, reuse revokes the family) and, when rotated,
    /// mints a new access token for the default audience with sid = the family. Audits TokenRefreshed or TokenReuse.
    /// </summary>
    Task<RefreshOutcome> RefreshAsync(string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// The user's live sessions (one row per refresh family, newest use first, at most <paramref name="max"/>), with the
    /// family whose id is <paramref name="currentSessionId"/> flagged as current. IP and user agent are cleaned for display.
    /// </summary>
    Task<IReadOnlyList<SessionResponse>> ListSessionsAsync(Guid userId, Guid? currentSessionId, int max, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes one session of the user. False when the family does not belong to the user (or does not exist): the caller
    /// cannot tell the two apart. Revoking an already revoked own session is true (idempotent).
    /// </summary>
    Task<bool> RevokeSessionAsync(Guid userId, Guid familyId, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class SignInService(
    IUserRepository users,
    IRefreshTokenRepository refreshRows,
    IRoleRepository roles,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    IAuthTimingGuard timingGuard,
    IPasswordHasher hasher,
    ILockoutService lockout,
    IRefreshTokenService refreshTokens,
    ITokenService tokens,
    TokenOptions tokenOptions,
    RefreshTokenOptions refreshOptions,
    ISessionLiveness liveness,
    IClock clock) : ISignInService
{
    public async Task<Result<SignedIn>> LoginAsync(LoginRequest request, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        string? normalizedEmail = EmailNormalizer.Normalize(request.Email);
        User? user = normalizedEmail is null ? null : await users.GetByNormalizedEmailAsync(normalizedEmail, cancellationToken);
        DateTime now = clock.UtcNow;

        // Why this account cannot sign in at all, for the audit only. Every refusal still costs one Verify (the guard
        // verifies a dummy hash) and gives the caller the same answer as a wrong password.
        string? refusal = user switch
        {
            null => "unknown",
            { IsActive: false } => "inactive",
            { EmailVerified: false } => "unverified",
            { PasswordHash: "" } => "no_password",
            { MfaEnabled: true } => "mfa_not_supported",
            _ when user.LockoutEndUtc > now => "locked",
            _ => null,
        };

        string password = request.Password ?? string.Empty;
        CredentialCheck check = await timingGuard.CheckPasswordAsync(password, user?.PasswordHash, accountUsable: refusal is null, cancellationToken);
        if (check == CredentialCheck.Invalid)
        {
            await RecordFailureAsync(user, refusal ?? "wrong_password", audit, now, cancellationToken);
            return Result.Failure<SignedIn>(AuthError.GenericInvalidCredentials);
        }

        // Re-login replaces the browser's previous session instead of leaving it alive with no cookie pointing at it.
        if (await refreshTokens.FindSessionAsync(presentedRefreshToken, cancellationToken) is RefreshSession previous)
        {
            await refreshTokens.RevokeFamilyForUserAsync(previous.FamilyId, previous.UserId, RefreshTokenRevokedReason.Logout, cancellationToken);
        }

        return Result.Success(await StartSessionAsync(user!, check == CredentialCheck.ValidNeedsRehash ? password : null, audit, cancellationToken));
    }

    public async Task<int> LogoutAsync(Guid? accessUserId, Guid? accessSessionId, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        int revoked = 0;
        if (accessUserId is Guid owner && accessSessionId is Guid sid)
        {
            revoked += await refreshTokens.RevokeFamilyForUserAsync(sid, owner, RefreshTokenRevokedReason.Logout, cancellationToken);
            liveness.Invalidate(sid);
        }

        // The refresh cookie still ends the session after the access cookie has expired and been dropped.
        RefreshSession? fromRefresh = await refreshTokens.FindSessionAsync(presentedRefreshToken, cancellationToken);
        if (fromRefresh is not null && (fromRefresh.FamilyId != accessSessionId || fromRefresh.UserId != accessUserId))
        {
            revoked += await refreshTokens.RevokeFamilyForUserAsync(fromRefresh.FamilyId, fromRefresh.UserId, RefreshTokenRevokedReason.Logout, cancellationToken);
            liveness.Invalidate(fromRefresh.FamilyId);
        }

        Guid? userId = accessUserId ?? fromRefresh?.UserId;
        if (userId is not null)
        {
            // Best effort: the sessions are already ended; a failed audit row must not turn that into an error.
            await audits.TryWriteAsync(AuditEvents.Logout(userId.Value, revoked), audit, cancellationToken);
        }

        return revoked;
    }

    public async Task<int> LogoutAllAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        int revoked = await refreshTokens.RevokeAllAsync(userId, RefreshTokenRevokedReason.LogoutAll, cancellationToken);
        liveness.InvalidateUser(userId);
        await audits.TryWriteAsync(AuditEvents.LogoutAll(userId, revoked), audit, cancellationToken);
        return revoked;
    }

    public async Task<RefreshOutcome> RefreshAsync(string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);

        // 1. Read-only preparation BEFORE rotating, so a failure here (database, signing) leaves the presented token
        //    untouched and the client can simply retry: the session, its user, the profile and the new access token.
        RefreshSession? session = await refreshTokens.FindSessionAsync(presentedRefreshToken, cancellationToken);
        if (session is null)
        {
            return new RefreshOutcome(RotationStatus.Invalid, null);
        }

        if (session.ClientApplicationId is not null)
        {
            // Cookie refresh is for the browser's own sessions only; a client-application family keeps its own audience
            // and is refreshed by the OAuth flow, never silently converted to the default audience.
            return new RefreshOutcome(RotationStatus.Invalid, null);
        }

        User? user = await users.GetByIdAsync(session.UserId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            await refreshTokens.RevokeFamilyForUserAsync(session.FamilyId, session.UserId, RefreshTokenRevokedReason.Admin, cancellationToken);
            return new RefreshOutcome(RotationStatus.Invalid, null);
        }

        Guid stamp = user.SecurityStamp;
        UserProfileResponse profile = await ProfileAsync(user, cancellationToken);
        AccessToken access = await tokens.CreateAccessTokenAsync(
            new AccessTokenRequest(user.Id, user.Email, user.DisplayName, profile.Roles, profile.Permissions, tokenOptions.DefaultAudience, null, session.FamilyId),
            cancellationToken);

        // 2. The rotation (its own transaction; may clear the change tracker on its retry).
        RotationResult rotation = await refreshTokens.RotateAsync(
            presentedRefreshToken!, new RefreshContext(audit.IpAddress ?? string.Empty, audit.UserAgent ?? string.Empty), cancellationToken);

        switch (rotation.Status)
        {
            case RotationStatus.Rotated when rotation.Token is IssuedRefreshToken token:
                // 3. After the commit nothing may fail silently: a session that cannot be completed is revoked, so no
                //    orphaned successor stays live and the client gets a clean 401 instead of a 500.
                string? rejection;
                try
                {
                    rejection = await CheckAfterRotationAsync(token, session, stamp, cancellationToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    rejection = "post_rotation_failure";
                }

                if (rejection is not null)
                {
                    await TryRevokeAsync(token.FamilyId, token.UserId, cancellationToken);
                    await audits.TryWriteAsync(AuditEvents.RefreshRejected(token.UserId, rejection), audit, cancellationToken);
                    return new RefreshOutcome(RotationStatus.Invalid, null);
                }

                await audits.TryWriteAsync(AuditEvents.TokenRefreshed(user.Id), audit, cancellationToken);
                return new RefreshOutcome(RotationStatus.Rotated, new SignedIn(access, token, profile));

            case RotationStatus.ReuseDetected when rotation.Reuse is TokenReuseDetected reuse:
                // Only a replay that actually revoked a live family is a theft signal. A token of a session that had
                // already ended (logout, password change, revoked session) is just rejected.
                await audits.TryWriteAsync(
                    reuse.RevokedCount > 0 ? AuditEvents.TokenReuse(reuse.UserId, reuse.RevokedCount) : AuditEvents.RefreshRejected(reuse.UserId, "ended_session_replayed"),
                    audit,
                    cancellationToken);
                return new RefreshOutcome(RotationStatus.ReuseDetected, null);

            default:
                return new RefreshOutcome(rotation.Status, null);
        }
    }

    /// <summary>
    /// Re-reads the user after the rotation (not the tracked copy): if the password changed (new SecurityStamp) or the
    /// account was disabled while refreshing, the successor must not live. Returns a rejection reason or null.
    /// </summary>
    private async Task<string?> CheckAfterRotationAsync(IssuedRefreshToken token, RefreshSession session, Guid stamp, CancellationToken cancellationToken)
    {
        if (token.FamilyId != session.FamilyId || token.UserId != session.UserId)
        {
            return "session_mismatch";
        }

        unitOfWork.ClearChanges();
        User? current = await users.GetByIdAsync(token.UserId, cancellationToken);
        return current switch
        {
            null => "unknown_user",
            { IsActive: false } or { EmailVerified: false } => "account_disabled",
            _ when current.SecurityStamp != stamp => "credentials_changed",
            _ => null,
        };
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

    public async Task<IReadOnlyList<SessionResponse>> ListSessionsAsync(Guid userId, Guid? currentSessionId, int max, CancellationToken cancellationToken)
    {
        IReadOnlyList<IRefreshSessionSummary> sessions = await refreshRows.GetActiveSessionsAsync(userId, clock.UtcNow, max, cancellationToken);
        return [.. sessions.Select(s => new SessionResponse(
            s.FamilyId, ForDisplay(s.IpAddress, 45), ForDisplay(s.UserAgent, 256), s.CreatedUtc, s.LastUsedUtc, s.FamilyId == currentSessionId))];
    }

    public async Task<bool> RevokeSessionAsync(Guid userId, Guid familyId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (!await refreshRows.FamilyBelongsToUserAsync(familyId, userId, cancellationToken))
        {
            return false;
        }

        int revoked = await refreshTokens.RevokeFamilyForUserAsync(familyId, userId, RefreshTokenRevokedReason.Logout, cancellationToken);
        liveness.Invalidate(familyId);
        if (revoked > 0)
        {
            await audits.TryWriteAsync(AuditEvents.SessionRevoked(userId, familyId), audit, cancellationToken);
        }

        return true;
    }

    public async Task<Result<UserProfileResponse>> GetProfileAsync(Guid userId, CancellationToken cancellationToken)
    {
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        return user is { IsActive: true }
            ? Result.Success(await ProfileAsync(user, cancellationToken))
            : Result.Failure<UserProfileResponse>(AuthError.NotFound);
    }

    /// <summary>
    /// The failed-attempt bookkeeping, the same database work for every account state: one lockout round trip (for an
    /// unknown email it looks up an id that cannot exist) and one audit insert. Audit rows are staged only after the
    /// lockout call, because its retry clears the change tracker.
    /// </summary>
    private async Task RecordFailureAsync(User? user, string reason, AuditContext audit, DateTime now, CancellationToken cancellationToken)
    {
        LockoutResult result = await lockout.RegisterFailureAsync(user?.Id ?? Guid.Empty, cancellationToken);

        await audits.StageAsync(AuditEvents.LoginFailed(user?.Id, reason), audit, cancellationToken);
        if (result.LockedOut is AccountLockedOut locked)
        {
            await audits.StageAsync(AuditEvents.Lockout(locked.UserId, locked.LockoutEndUtc, locked.Level), audit, cancellationToken);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private async Task<SignedIn> StartSessionAsync(User user, string? rehashPassword, AuditContext audit, CancellationToken cancellationToken)
    {
        // May clear the change tracker on a retry, so nothing is staged before it, and the user is read again after it.
        await lockout.ResetAsync(user.Id, cancellationToken);
        await MakeRoomForSessionAsync(user.Id, audit, cancellationToken);
        string? newHash = rehashPassword is null ? null : await hasher.HashAsync(rehashPassword, cancellationToken);
        RefreshContext refreshContext = new(audit.IpAddress ?? string.Empty, audit.UserAgent ?? string.Empty);

        IssuedRefreshToken refresh;
        try
        {
            refresh = await IssueWithAuditAsync(user.Id, await users.GetByIdAsync(user.Id, cancellationToken), newHash, refreshContext, audit, cancellationToken);
        }
        catch (ConcurrencyConflictException)
        {
            // The user row changed meanwhile (e.g. a concurrent failed attempt). Skip the optional user updates
            // (last login, rehash) and start the session anyway.
            unitOfWork.ClearChanges();
            refresh = await IssueWithAuditAsync(user.Id, null, null, refreshContext, audit, cancellationToken);
        }

        UserProfileResponse profile = await ProfileAsync(user, cancellationToken);
        AccessToken access = await tokens.CreateAccessTokenAsync(
            new AccessTokenRequest(user.Id, user.Email, user.DisplayName, profile.Roles, profile.Permissions, tokenOptions.DefaultAudience, null, refresh.FamilyId),
            cancellationToken);
        return new SignedIn(access, refresh, profile);
    }

    /// <summary>
    /// Session cap (T15 review): before a new family is issued, the least recently used live families beyond
    /// MaxSessionsPerUser - 1 are revoked, each audited as SessionRevoked with reason session_cap. Done before the issue,
    /// so a failure here fails the login without leaving a new session behind. Two logins at the same moment can
    /// briefly leave one session over the cap; the next login trims it.
    /// </summary>
    private async Task MakeRoomForSessionAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        int keep = refreshOptions.MaxSessionsPerUser - 1;
        IReadOnlyList<IRefreshSessionSummary> live = await refreshRows.GetActiveSessionsAsync(userId, clock.UtcNow, refreshOptions.MaxSessionsPerUser + 100, cancellationToken);
        foreach (IRefreshSessionSummary oldest in live.Skip(keep))
        {
            if (await refreshTokens.RevokeFamilyForUserAsync(oldest.FamilyId, userId, RefreshTokenRevokedReason.Admin, cancellationToken) > 0)
            {
                liveness.Invalidate(oldest.FamilyId);
                await audits.TryWriteAsync(AuditEvents.SessionRevoked(userId, oldest.FamilyId, "session_cap"), audit, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Stages the LoginSucceeded row (and, for a tracked user, last login and a rehash) and saves them in the same save
    /// that creates the new refresh family.
    /// </summary>
    private async Task<IssuedRefreshToken> IssueWithAuditAsync(
        Guid userId, User? tracked, string? newHash, RefreshContext refreshContext, AuditContext audit, CancellationToken cancellationToken)
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

        await audits.StageAsync(AuditEvents.LoginSucceeded(userId), audit, cancellationToken);
        return await refreshTokens.IssueAsync(userId, null, refreshContext, cancellationToken);
    }

    private async Task<UserProfileResponse> ProfileAsync(User user, CancellationToken cancellationToken)
    {
        IReadOnlyList<Role> userRoles = await roles.GetForUserAsync(user.Id, null, cancellationToken);
        IReadOnlyList<string> permissions = await roles.GetPermissionCodesForUserAsync(user.Id, null, cancellationToken);
        return new UserProfileResponse(
            user.Id,
            user.Email,
            user.EmailVerified,
            user.DisplayName,
            user.MfaEnabled,
            [.. userRoles.Select(r => r.Name).Order(StringComparer.Ordinal)],
            [.. permissions.Order(StringComparer.Ordinal)]);
    }

    /// <summary>
    /// For display only: control and invisible format characters and the HTML brackets &lt; &gt; removed (they never
    /// occur in a real IP address or user agent), trimmed, capped. The stored value is not changed.
    /// </summary>
    private static string ForDisplay(string value, int max)
    {
        string clean = new string([.. value.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format && c is not ('<' or '>' or '&' or '"' or '\''))]).Trim();
        return clean.Length <= max ? clean : clean[..max];
    }
}
