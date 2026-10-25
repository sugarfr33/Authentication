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

/// <summary>
/// Outcome of a password login: a started <see cref="Session"/>, or (MFA, T21) the <see cref="MfaChallenge"/> to send
/// as the challenge cookie, or neither (the one generic refusal).
/// </summary>
public sealed record LoginResult(SignedIn? Session, string? MfaChallenge)
{
    public bool IsSuccess => Session is not null;

    public bool MfaRequired => MfaChallenge is not null;
}

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
    Task<LoginResult> LoginAsync(LoginRequest request, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken);

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
    IAuditService audits,
    IUnitOfWork unitOfWork,
    IAuthTimingGuard timingGuard,
    ILockoutService lockout,
    IRefreshTokenService refreshTokens,
    ISessionRefresher refresher,
    IAccessProfileBuilder profiles,
    ISessionLiveness liveness,
    ISessionEndedPublisher sessionsEnded,
    IBrowserSessionStarter starter,
    Mfa.IMfaChallenges mfaChallenges,
    Mfa.MfaOptions mfaOptions,
    IClock clock) : ISignInService
{
    public async Task<LoginResult> LoginAsync(LoginRequest request, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
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
            // MFA turned off by configuration while this account has it: fail closed, never a password-only sign-in.
            { MfaEnabled: true } when !mfaOptions.Enabled => "mfa_unavailable",
            _ when user.LockoutEndUtc > now => "locked",
            _ => null,
        };

        string password = request.Password ?? string.Empty;
        CredentialCheck check = await timingGuard.CheckPasswordAsync(password, user?.PasswordHash, accountUsable: refusal is null, cancellationToken);
        if (check == CredentialCheck.Invalid)
        {
            await RecordFailureAsync(user, refusal ?? "wrong_password", audit, now, cancellationToken);
            return new LoginResult(null, null);
        }

        if (user!.MfaEnabled)
        {
            // Password proven, second factor pending (T21): no session and NO lockout reset until the factor succeeds.
            return new LoginResult(null, await mfaChallenges.CreateAsync(user, audit.UserAgent, cancellationToken));
        }

        return new LoginResult(await starter.StartAsync(user, presentedRefreshToken, check == CredentialCheck.ValidNeedsRehash ? password : null, null, audit, cancellationToken), null);
    }

    public async Task<int> LogoutAsync(Guid? accessUserId, Guid? accessSessionId, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);

        // The refresh cookie still ends the session after the access cookie has expired and been dropped.
        RefreshSession? fromRefresh = await refreshTokens.FindSessionAsync(presentedRefreshToken, cancellationToken);

        // Single logout (T20) FIRST: the user's application sessions end before the browser family is revoked, so if a
        // listener fails (SessionEndFailedException) the browser session is still there and the sign-out can be retried.
        foreach (Guid ended in new[] { accessUserId, fromRefresh?.UserId }.OfType<Guid>().Distinct())
        {
            await sessionsEnded.PublishAsync(
                new SessionEnded(SessionEndScope.Browser, SessionEndCause.Logout, ended, ended == accessUserId ? accessSessionId : fromRefresh?.FamilyId), audit, cancellationToken);
        }

        int revoked = 0;
        if (accessUserId is Guid owner && accessSessionId is Guid sid)
        {
            revoked += await refreshTokens.RevokeFamilyForUserAsync(sid, owner, RefreshTokenRevokedReason.Logout, cancellationToken);
            liveness.Invalidate(sid);
        }

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
        await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.All, SessionEndCause.LogoutAll, userId), audit, cancellationToken);
        return revoked;
    }

    public Task<RefreshOutcome> RefreshAsync(string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);

        // Cookie refresh is for the browser's own sessions only (application null): a client-application family keeps
        // its own audience and is refreshed by the OAuth flow, never silently converted to the default audience.
        return refresher.RefreshAsync(
            presentedRefreshToken, null, new RefreshContext(audit.IpAddress ?? string.Empty, audit.UserAgent ?? string.Empty), audit, cancellationToken);
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

        // A browser session ends the user's application sessions first (retryable, as for logout); an application
        // session ends alone.
        Guid? application = await refreshRows.GetFamilyClientApplicationIdAsync(familyId, userId, cancellationToken);
        SessionEnded ended = application is null
            ? new SessionEnded(SessionEndScope.Browser, SessionEndCause.SessionRevoked, userId, familyId)
            : new SessionEnded(SessionEndScope.Application, SessionEndCause.SessionRevoked, userId, familyId, application);
        if (ended.Scope == SessionEndScope.Browser)
        {
            await sessionsEnded.PublishAsync(ended, audit, cancellationToken);
        }

        int revoked = await refreshTokens.RevokeFamilyForUserAsync(familyId, userId, RefreshTokenRevokedReason.Logout, cancellationToken);
        liveness.Invalidate(familyId);
        if (revoked > 0)
        {
            await audits.TryWriteAsync(AuditEvents.SessionRevoked(userId, familyId), audit, cancellationToken);
            if (ended.Scope == SessionEndScope.Application)
            {
                await sessionsEnded.PublishAsync(ended, audit, cancellationToken);
            }
        }

        return true;
    }

    public async Task<Result<UserProfileResponse>> GetProfileAsync(Guid userId, CancellationToken cancellationToken)
    {
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        return user is { IsActive: true }
            ? Result.Success(await profiles.BuildProfileAsync(user, null, cancellationToken))
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
