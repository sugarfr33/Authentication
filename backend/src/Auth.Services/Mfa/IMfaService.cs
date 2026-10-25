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

    /// <summary>A valid code for the pending secret turns MFA on, returns the 10 recovery codes once and ends every session.</summary>
    Task<Result<IReadOnlyList<string>>> ConfirmAsync(Guid userId, string? code, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>With the password and a valid TOTP code: invalidates every recovery code and returns 10 new ones.</summary>
    Task<Result<IReadOnlyList<string>>> RegenerateRecoveryCodesAsync(Guid userId, string? password, string? code, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>With the password and a valid TOTP or recovery code: turns MFA off and ends every session.</summary>
    Task<Result> DisableAsync(Guid userId, string? password, string? code, bool isRecoveryCode, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Administrative reset (no endpoint): turns MFA off without factors and ends every session. False for an unknown user.</summary>
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
    private const int RecoveryCodeLength = 10;
    private const string RecoveryAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

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
        user.MfaSecretEncrypted = await crypto.ProtectAsync(user.Id, new MfaSecret(secret, 0), cancellationToken);
        user.UpdatedUtc = clock.UtcNow;
        await audits.StageAsync(AuditEvents.MfaEnabled(user.Id, "enrollment_started"), audit, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

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
        if (user is not { IsActive: true } || user.MfaEnabled || user.MfaSecretEncrypted is null)
        {
            return Result.Failure<IReadOnlyList<string>>(AuthError.ValidationFailed);
        }

        string? failure = await CheckTotpAsync(user, code, cancellationToken);
        if (failure is not null)
        {
            await FailAsync(user, failure, audit, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AuthError.InvalidMfaCode);
        }

        user.MfaEnabled = true;
        IReadOnlyList<string> codes = await ChangeCredentialsAsync(user, issueRecoveryCodes: true, AuditEvents.MfaEnabled(user.Id, "enrolled"), audit, cancellationToken);
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

        string? failure = !await PasswordMatchesAsync(user, password, cancellationToken) ? "wrong_password" : await CheckTotpAsync(user, code, cancellationToken);
        if (failure is not null)
        {
            await FailAsync(user, failure, audit, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AuthError.InvalidMfaCode);
        }

        DateTime now = clock.UtcNow;
        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await recoveryCodes.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        IReadOnlyList<string> codes = await AddRecoveryCodesAsync(user.Id, now, cancellationToken);
        user.UpdatedUtc = now;
        await audits.StageAsync(AuditEvents.MfaEnabled(user.Id, "regenerated"), audit, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Result.Success(codes);
    }

    public async Task<Result> DisableAsync(Guid userId, string? password, string? code, bool isRecoveryCode, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, MfaEnabled: true })
        {
            return Result.Failure(AuthError.ValidationFailed);
        }

        string? failure = !await PasswordMatchesAsync(user, password, cancellationToken)
            ? "wrong_password"
            : isRecoveryCode ? await UseRecoveryCodeAsync(user, code, cancellationToken) : await CheckTotpAsync(user, code, cancellationToken);
        if (failure is not null)
        {
            await FailAsync(user, failure, audit, cancellationToken);
            return Result.Failure(AuthError.InvalidMfaCode);
        }

        await TurnOffAsync(user, "disabled", audit, cancellationToken);
        await EndSessionsAsync(user.Id, SessionEndCause.MfaDisabled, audit, cancellationToken);
        return Result.Success();
    }

    public async Task<bool> ResetAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        await TurnOffAsync(user, "reset", audit, cancellationToken);
        await EndSessionsAsync(user.Id, SessionEndCause.MfaReset, audit, cancellationToken);
        return true;
    }

    public async Task<Result<SignedIn>> VerifyLoginAsync(string? challenge, string? code, bool isRecoveryCode, string? presentedRefreshToken, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        Guid? userId = challenges.ReadUserId(challenge);
        User? user = userId is Guid id ? await users.GetByIdAsync(id, cancellationToken) : null;
        if (user is not { IsActive: true, EmailVerified: true, MfaEnabled: true } || !await challenges.VerifyAsync(challenge!, user, audit.UserAgent, cancellationToken))
        {
            // Expired, altered, already used or for a changed account: no user to charge, the same answer.
            await audits.TryWriteAsync(AuditEvents.MfaFailed(user?.Id, "bad_challenge"), audit, cancellationToken);
            return Result.Failure<SignedIn>(AuthError.InvalidMfaCode);
        }

        string? failure = user.LockoutEndUtc > clock.UtcNow
            ? "locked"
            : isRecoveryCode ? await UseRecoveryCodeAsync(user, code, cancellationToken) : await CheckTotpAsync(user, code, cancellationToken);
        if (failure is null)
        {
            try
            {
                // Persists the new last step (TOTP) or a fresh nonce (recovery code): the challenge cannot be used again.
                await unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (ConcurrencyConflictException)
            {
                unitOfWork.ClearChanges();
                failure = "replayed";
            }
        }

        if (failure is not null)
        {
            await FailAsync(user, failure, audit, cancellationToken);
            return Result.Failure<SignedIn>(AuthError.InvalidMfaCode);
        }

        AuditEvent factor = isRecoveryCode ? AuditEvents.MfaRecoveryCodeUsed(user.Id) : AuditEvents.MfaVerified(user.Id);
        return Result.Success(await starter.StartAsync(user, presentedRefreshToken, null, factor, audit, cancellationToken));
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
                return Totp.IsReplay(secret.Secret, code, now, secret.LastUsedStep) ? "replayed" : "wrong_code";
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
    /// Spends a recovery code with the conditional UPDATE (single use) and stages a re-encrypted blob (new nonce), so a
    /// login challenge issued before cannot be used again. Returns a failure reason or null.
    /// </summary>
    private async Task<string?> UseRecoveryCodeAsync(User user, string? code, CancellationToken cancellationToken)
    {
        string? normalized = NormalizeRecoveryCode(code);
        if (normalized is null)
        {
            return "wrong_recovery_code";
        }

        MfaRecoveryCode? row = await recoveryCodes.GetByHashAsync(await crypto.RecoveryHashAsync(normalized, cancellationToken), cancellationToken);
        if (row is null || row.UserId != user.Id || row.UsedUtc is not null || !await recoveryCodes.TryMarkUsedAsync(row.Id, clock.UtcNow, cancellationToken))
        {
            return "wrong_recovery_code";
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
    /// In one transaction: a new SecurityStamp, the recovery codes replaced (or just invalidated), every refresh family
    /// revoked, and the audit row. Returns the new plain recovery codes (empty when none are issued).
    /// </summary>
    private async Task<IReadOnlyList<string>> ChangeCredentialsAsync(User user, bool issueRecoveryCodes, AuditEvent auditEvent, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        user.SecurityStamp = Guid.NewGuid();
        user.UpdatedUtc = now;
        await recoveryCodes.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        IReadOnlyList<string> codes = issueRecoveryCodes ? await AddRecoveryCodesAsync(user.Id, now, cancellationToken) : [];
        await refreshRows.RevokeAllForUserAsync(user.Id, RefreshTokenRevokedReason.PasswordChange, now, cancellationToken);
        await audits.StageAsync(auditEvent, audit, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return codes;
    }

    private async Task TurnOffAsync(User user, string action, AuditContext audit, CancellationToken cancellationToken)
    {
        user.MfaEnabled = false;
        user.MfaSecretEncrypted = null;
        await ChangeCredentialsAsync(user, issueRecoveryCodes: false, AuditEvents.MfaEnabled(user.Id, action), audit, cancellationToken);
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
