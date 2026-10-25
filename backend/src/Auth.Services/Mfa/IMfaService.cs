using System.Data;
using System.Security.Cryptography;
using Auth.Contracts;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Security;

namespace Auth.Services.Mfa;

/// <summary>What the enroll step shows once: the otpauth URI (for a QR code) and the same key for manual entry.</summary>
public sealed record MfaEnrollment(string OtpAuthUri, string ManualEntryKey);

/// <summary>
/// Optional TOTP MFA (T21, docs/mfa-totp.md). Every wrong factor (password, TOTP code, recovery code) counts toward the
/// shared lockout like a wrong password and is audited MfaFailed with a reason word; codes, secrets and challenges never
/// reach a log or an audit row. Enabling, disabling and resetting MFA end every session of the user.
/// </summary>
public interface IMfaService
{
    /// <summary>Starts (or restarts) enrollment after re-checking the password. ValidationFailed when MFA is already on.</summary>
    Task<Result<MfaEnrollment>> EnrollAsync(Guid userId, string? password, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// A valid code for the pending secret (at most <see cref="MfaService.PendingEnrollmentLifetime"/> old) turns MFA on,
    /// returns the 10 recovery codes once and ends every session. ValidationFailed (no strike) when nothing is pending,
    /// the pending secret expired, or a concurrent change won.
    /// </summary>
    Task<Result<IReadOnlyList<string>>> ConfirmAsync(Guid userId, string? code, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>With the password and a valid TOTP code: invalidates every recovery code and returns 10 new ones.</summary>
    Task<Result<IReadOnlyList<string>>> RegenerateRecoveryCodesAsync(Guid userId, string? password, string? code, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>With the password and a valid TOTP or recovery code: turns MFA off and ends every session.</summary>
    Task<Result> DisableAsync(Guid userId, string? password, string? code, bool isRecoveryCode, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Administrative reset (no endpoint; docs/mfa-admin-recovery.md): turns MFA off without factors and ends every
    /// session. False for an unknown user; retries a lost race twice, then throws ConcurrencyConflictException.
    /// </summary>
    Task<bool> ResetAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// The second login step: the challenge cookie plus a TOTP or recovery code. Success starts the browser session (the
    /// shared starter); every failure is the same InvalidMfaCode.
    /// </summary>
    Task<Result<SignedIn>> VerifyLoginAsync(string? challenge, string? code, bool isRecoveryCode, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Loads and checks the MFA keys; throws when one is missing or malformed (the host calls it at startup when MFA is on).</summary>
    Task ValidateKeysAsync(CancellationToken cancellationToken);
}

internal sealed class MfaService(
    IUserRepository users,
    IOneTimeTokenRepository<MfaRecoveryCode> recoveryCodes,
    IRefreshTokenRepository refreshRows,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    IAuthTimingGuard timingGuard,
    ILockoutService lockout,
    IMfaCrypto crypto,
    IMfaChallenges challenges,
    IBrowserSessionStarter starter,
    ISessionLiveness liveness,
    ISessionEndedPublisher sessionsEnded,
    MfaOptions options,
    IClock clock) : IMfaService
{
    public const int RecoveryCodeCount = 10;

    /// <summary>How long an unconfirmed enrollment secret can be confirmed, counted from the last change of the account row.</summary>
    public static readonly TimeSpan PendingEnrollmentLifetime = TimeSpan.FromMinutes(15);

    private const int RecoveryCodeLength = 10;
    private const string RecoveryAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    // Internal outcome of a transactional step that lost a RowVersion race: never a strike, never a burned code.
    private const string Conflict = "conflict";
    private const string Replayed = "replayed";

    public Task ValidateKeysAsync(CancellationToken cancellationToken) => crypto.ValidateKeysAsync(cancellationToken);

    public async Task<Result<MfaEnrollment>> EnrollAsync(Guid userId, string? password, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            return Result.Failure<MfaEnrollment>(AuthError.NotFound);
        }

        if (user.MfaEnabled)
        {
            return Result.Failure<MfaEnrollment>(AuthError.ValidationFailed);
        }

        if (!await PasswordMatchesAsync(user, password, cancellationToken))
        {
            await FailAsync(user, "wrong_password", audit, cancellationToken);
            return Result.Failure<MfaEnrollment>(AuthError.GenericInvalidCredentials);
        }

        byte[] secret = RandomNumberGenerator.GetBytes(20);
        try
        {
            user.MfaSecretEncrypted = await crypto.ProtectAsync(user.Id, new MfaSecret(secret, 0), cancellationToken);
            user.UpdatedUtc = clock.UtcNow;
            await audits.StageAsync(AuditEvents.MfaEnrollmentStarted(user.Id), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (ConcurrencyConflictException)
        {
            // A concurrent enroll or account change won: the caller can simply ask again.
            unitOfWork.ClearChanges();
            CryptographicOperations.ZeroMemory(secret);
            return Result.Failure<MfaEnrollment>(AuthError.ValidationFailed);
        }

        string key = Base32.Encode(secret);
        CryptographicOperations.ZeroMemory(secret);
        string label = Uri.EscapeDataString(options.Issuer + ":" + user.Email);
        return Result.Success(new MfaEnrollment(
            "otpauth://totp/" + label + "?secret=" + key + "&issuer=" + Uri.EscapeDataString(options.Issuer) + "&algorithm=SHA1&digits=6&period=30",
            key));
    }

    public async Task<Result<IReadOnlyList<string>>> ConfirmAsync(Guid userId, string? code, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true } || user.MfaEnabled || user.MfaSecretEncrypted is null || user.UpdatedUtc + PendingEnrollmentLifetime < clock.UtcNow)
        {
            // Nothing pending, already on, or the pending secret expired (enroll again).
            return Result.Failure<IReadOnlyList<string>>(AuthError.ValidationFailed);
        }

        IReadOnlyList<string> codes = [];
        string? failure = await CommitAsync(
            () => CheckTotpAsync(user, code, cancellationToken),
            async () =>
            {
                user.MfaEnabled = true;
                codes = await StageCredentialChangeAsync(user, issueRecoveryCodes: true, AuditEvents.MfaEnabled(user.Id, "enrolled"), audit, cancellationToken);
            },
            cancellationToken);
        if (failure is not null)
        {
            return Result.Failure<IReadOnlyList<string>>(await RefuseAsync(user, failure, audit, cancellationToken));
        }

        await EndSessionsAsync(user.Id, SessionEndCause.MfaEnrolled, audit, cancellationToken);
        return Result.Success(codes);
    }

    public async Task<Result<IReadOnlyList<string>>> RegenerateRecoveryCodesAsync(Guid userId, string? password, string? code, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, MfaEnabled: true })
        {
            return Result.Failure<IReadOnlyList<string>>(AuthError.ValidationFailed);
        }

        if (!await PasswordMatchesAsync(user, password, cancellationToken))
        {
            await FailAsync(user, "wrong_password", audit, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AuthError.InvalidMfaCode);
        }

        IReadOnlyList<string> codes = [];
        string? failure = await CommitAsync(
            () => CheckTotpAsync(user, code, cancellationToken),
            async () =>
            {
                DateTime now = clock.UtcNow;
                await recoveryCodes.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
                codes = await AddRecoveryCodesAsync(user.Id, now, cancellationToken);
                await audits.StageAsync(AuditEvents.MfaEnabled(user.Id, "regenerated"), audit, cancellationToken);
            },
            cancellationToken);
        return failure is null ? Result.Success(codes) : Result.Failure<IReadOnlyList<string>>(await RefuseAsync(user, failure, audit, cancellationToken));
    }

    public async Task<Result> DisableAsync(Guid userId, string? password, string? code, bool isRecoveryCode, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, MfaEnabled: true })
        {
            return Result.Failure(AuthError.ValidationFailed);
        }

        if (!await PasswordMatchesAsync(user, password, cancellationToken))
        {
            await FailAsync(user, "wrong_password", audit, cancellationToken);
            return Result.Failure(AuthError.InvalidMfaCode);
        }

        // The recovery code is spent inside the same transaction as the change, so a lost race does not burn it.
        string? failure = await CommitAsync(
            () => isRecoveryCode ? UseRecoveryCodeAsync(user, code, cancellationToken) : CheckTotpAsync(user, code, cancellationToken),
            () => StageTurnOffAsync(user, "disabled", audit, cancellationToken),
            cancellationToken);
        if (failure is not null)
        {
            return Result.Failure(await RefuseAsync(user, failure, audit, cancellationToken));
        }

        await EndSessionsAsync(user.Id, SessionEndCause.MfaDisabled, audit, cancellationToken);
        return Result.Success();
    }

    public async Task<bool> ResetAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            unitOfWork.ClearChanges();
            User? user = await users.GetByIdAsync(userId, cancellationToken);
            if (user is null)
            {
                return false;
            }

            if (await CommitAsync(() => Task.FromResult<string?>(null), () => StageTurnOffAsync(user, "reset", audit, cancellationToken), cancellationToken) is null)
            {
                await EndSessionsAsync(user.Id, SessionEndCause.MfaReset, audit, cancellationToken);
                return true;
            }
        }

        throw new ConcurrencyConflictException("The account kept changing during the MFA reset; run it again.");
    }

    public async Task<Result<SignedIn>> VerifyLoginAsync(string? challenge, string? code, bool isRecoveryCode, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        Guid? userId = challenges.ReadUserId(challenge);

        // A lost race (a concurrent lockout write, a double submit) or an apparent replay is checked once more against
        // fresh state: when a concurrent sign-in used this challenge, it is now stale and nothing is charged; a code
        // that is still a replay against the fresh state is a genuine one and counts.
        for (int attempt = 0; ; attempt++)
        {
            unitOfWork.ClearChanges();
            User? user = userId is Guid id ? await users.GetByIdAsync(id, cancellationToken) : null;
            if (user is not { IsActive: true, EmailVerified: true, MfaEnabled: true } || !await challenges.VerifyAsync(challenge!, user, audit.UserAgent, cancellationToken))
            {
                // Expired, altered, already used or for a changed account. The challenge is not trusted here, so the row
                // names no user (anyone can forge one naming a victim) and nothing is charged.
                await audits.TryWriteAsync(AuditEvents.MfaFailed(null, "bad_challenge"), audit, cancellationToken);
                return Result.Failure<SignedIn>(AuthError.InvalidMfaCode);
            }

            // Commits the new last step (TOTP) or the spent code with a fresh nonce (recovery code), in one transaction:
            // the challenge cannot be used again, and a lost race rolls the code spend back.
            string? failure = user.LockoutEndUtc > clock.UtcNow
                ? "locked"
                : await CommitAsync(
                    () => isRecoveryCode ? UseRecoveryCodeAsync(user, code, cancellationToken) : CheckTotpAsync(user, code, cancellationToken),
                    () => Task.CompletedTask,
                    cancellationToken);
            if (failure is null)
            {
                AuditEvent factor = isRecoveryCode ? AuditEvents.MfaRecoveryCodeUsed(user.Id) : AuditEvents.MfaVerified(user.Id);
                return Result.Success(await starter.StartAsync(user, presentedRefreshToken, null, factor, audit, cancellationToken));
            }

            if (failure is Conflict or Replayed && attempt == 0)
            {
                continue;
            }

            if (failure is Conflict)
            {
                await audits.TryWriteAsync(AuditEvents.MfaFailed(user.Id, Conflict), audit, cancellationToken);
                return Result.Failure<SignedIn>(AuthError.InvalidMfaCode);
            }

            await FailAsync(user, failure, audit, cancellationToken);
            return Result.Failure<SignedIn>(AuthError.InvalidMfaCode);
        }
    }

    /// <summary>Normalizes recovery-code input: upper case, without spaces or hyphens; null unless 10 alphabet letters.</summary>
    internal static string? NormalizeRecoveryCode(string? code)
    {
        if (code is null || code.Length > 32)
        {
            return null;
        }

        string compact = new([.. code.ToUpperInvariant().Where(c => c is not (' ' or '-'))]);
        return compact.Length == RecoveryCodeLength && compact.All(c => RecoveryAlphabet.Contains(c, StringComparison.Ordinal)) ? compact : null;
    }

    private async Task<bool> PasswordMatchesAsync(User user, string? password, CancellationToken cancellationToken) =>
        await timingGuard.CheckPasswordAsync(password ?? string.Empty, user.PasswordHash, accountUsable: user.PasswordHash.Length > 0, cancellationToken) != CredentialCheck.Invalid;

    /// <summary>
    /// In one transaction: the factor check (which may spend a recovery code and stages the new blob), then the staged
    /// change and the save. Returns null on success, the factor's failure reason, or <see cref="Conflict"/> when the save
    /// lost a RowVersion race (everything rolled back, the tracker cleared).
    /// </summary>
    private async Task<string?> CommitAsync(Func<Task<string?>> factor, Func<Task> change, CancellationToken cancellationToken)
    {
        try
        {
            await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
            string? failure = await factor();
            if (failure is not null)
            {
                return failure;
            }

            await change();
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return null;
        }
        catch (ConcurrencyConflictException)
        {
            unitOfWork.ClearChanges();
            return Conflict;
        }
    }

    /// <summary>A refused management step: a lost race is a 409 with no strike; a wrong factor counts toward the lockout.</summary>
    private async Task<AuthError> RefuseAsync(User user, string failure, AuditContext audit, CancellationToken cancellationToken)
    {
        if (failure is Conflict)
        {
            return AuthError.ValidationFailed;
        }

        await FailAsync(user, failure, audit, cancellationToken);
        return AuthError.InvalidMfaCode;
    }

    /// <summary>Checks a TOTP code; on success stages the new last step in the (tracked) user's blob. Returns a failure reason or null.</summary>
    private async Task<string?> CheckTotpAsync(User user, string? code, CancellationToken cancellationToken)
    {
        MfaSecret? secret = await crypto.UnprotectAsync(user.Id, user.MfaSecretEncrypted, cancellationToken);
        if (secret is null)
        {
            return "wrong_code";
        }

        try
        {
            long now = Totp.StepAt(clock.UtcNow);
            if (Totp.Match(secret.Secret, code, now, secret.LastUsedStep) is not long step)
            {
                return Totp.IsReplay(secret.Secret, code, now, secret.LastUsedStep) ? Replayed : "wrong_code";
            }

            user.MfaSecretEncrypted = await crypto.ProtectAsync(user.Id, secret with { LastUsedStep = step }, cancellationToken);
            user.UpdatedUtc = clock.UtcNow;
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret.Secret);
        }
    }

    /// <summary>
    /// Spends a recovery code with the conditional UPDATE (single use; called inside <see cref="CommitAsync"/>, so a lost
    /// race rolls it back) and stages a re-encrypted blob (new nonce), so a login challenge issued before cannot be used
    /// again. Returns a failure reason (<see cref="Replayed"/> for this user's already used code) or null.
    /// </summary>
    private async Task<string?> UseRecoveryCodeAsync(User user, string? code, CancellationToken cancellationToken)
    {
        string? normalized = NormalizeRecoveryCode(code);
        if (normalized is null)
        {
            return "wrong_recovery_code";
        }

        MfaRecoveryCode? row = await recoveryCodes.GetByHashAsync(await crypto.RecoveryHashAsync(normalized, cancellationToken), cancellationToken);
        if (row is null || row.UserId != user.Id)
        {
            return "wrong_recovery_code";
        }

        if (row.UsedUtc is not null || !await recoveryCodes.TryMarkUsedAsync(row.Id, clock.UtcNow, cancellationToken))
        {
            return Replayed;
        }

        if (await crypto.UnprotectAsync(user.Id, user.MfaSecretEncrypted, cancellationToken) is MfaSecret secret)
        {
            user.MfaSecretEncrypted = await crypto.ProtectAsync(user.Id, secret, cancellationToken);
            CryptographicOperations.ZeroMemory(secret.Secret);
        }

        user.UpdatedUtc = clock.UtcNow;
        return null;
    }

    /// <summary>
    /// A wrong factor: one lockout round trip (the shared service, as a wrong password), then the MfaFailed row and, when
    /// the account just locked, the Lockout row. Audit rows are staged after the lockout call (its retry clears the tracker).
    /// </summary>
    private async Task FailAsync(User user, string reason, AuditContext audit, CancellationToken cancellationToken)
    {
        unitOfWork.ClearChanges();
        LockoutResult result = await lockout.RegisterFailureAsync(user.Id, cancellationToken);
        await audits.StageAsync(AuditEvents.MfaFailed(user.Id, reason), audit, cancellationToken);
        if (result.LockedOut is AccountLockedOut locked)
        {
            await audits.StageAsync(AuditEvents.Lockout(locked.UserId, locked.LockoutEndUtc, locked.Level), audit, cancellationToken);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Stages, inside the caller's transaction: a new SecurityStamp, the recovery codes replaced (or just invalidated),
    /// every refresh family revoked, and the audit row. Returns the new plain recovery codes (empty when none are issued).
    /// RefreshToken.RevokedReason is CHECK-constrained, so the rows keep PasswordChange (a credential change); the real
    /// cause is in the audit row and in the SessionEnded cause.
    /// </summary>
    private async Task<IReadOnlyList<string>> StageCredentialChangeAsync(User user, bool issueRecoveryCodes, AuditEvent auditEvent, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        user.SecurityStamp = Guid.NewGuid();
        user.UpdatedUtc = now;
        await recoveryCodes.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        IReadOnlyList<string> codes = issueRecoveryCodes ? await AddRecoveryCodesAsync(user.Id, now, cancellationToken) : [];
        await refreshRows.RevokeAllForUserAsync(user.Id, RefreshTokenRevokedReason.PasswordChange, now, cancellationToken);
        await audits.StageAsync(auditEvent, audit, cancellationToken);
        return codes;
    }

    private async Task StageTurnOffAsync(User user, string action, AuditContext audit, CancellationToken cancellationToken)
    {
        user.MfaEnabled = false;
        user.MfaSecretEncrypted = null;
        await StageCredentialChangeAsync(user, issueRecoveryCodes: false, AuditEvents.MfaDisabled(user.Id, action), audit, cancellationToken);
    }

    private async Task EndSessionsAsync(Guid userId, SessionEndCause cause, AuditContext audit, CancellationToken cancellationToken)
    {
        liveness.InvalidateUser(userId);
        await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.All, cause, userId), audit, cancellationToken);
    }

    private async Task<IReadOnlyList<string>> AddRecoveryCodesAsync(Guid userId, DateTime now, CancellationToken cancellationToken)
    {
        List<string> shown = [];
        for (int i = 0; i < RecoveryCodeCount; i++)
        {
            string code = new(RandomNumberGenerator.GetItems<char>(RecoveryAlphabet, RecoveryCodeLength));
            await recoveryCodes.AddAsync(new MfaRecoveryCode { UserId = userId, CodeHash = await crypto.RecoveryHashAsync(code, cancellationToken), CreatedUtc = now }, cancellationToken);
            shown.Add(code[..5] + "-" + code[5..]);
        }

        return shown;
    }
}
