using System.Data;
using System.Globalization;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Auth.Services.Tokens;

namespace Auth.Services.Accounts;

/// <summary>Outcome of a password operation: success, validation errors (ValidationFailed), or one generic <see cref="AuthError"/>.</summary>
public sealed record PasswordResult(AuthError? Error, IReadOnlyDictionary<string, string[]>? ValidationErrors)
{
    public static readonly PasswordResult Ok = new(null, null);

    public bool IsSuccess => Error is null;

    internal static PasswordResult Invalid(IReadOnlyDictionary<string, string[]> errors) => new(AuthError.ValidationFailed, errors);

    internal static PasswordResult Failure(AuthError error) => new(error, null);
}

/// <summary>Forgot, reset and change password (T14).</summary>
public interface IPasswordService
{
    /// <summary>
    /// Always <see cref="PasswordResult.Ok"/> for a well-formed email, whether or not it belongs to an account that can
    /// reset. Every path does the same work: one lookup, one save, one email (a reset link only for an active account
    /// with a verified email; otherwise a notice that explains why no link was sent).
    /// </summary>
    Task<PasswordResult> ForgotPasswordAsync(ForgotPasswordRequest request, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Sets a new password with a reset link: single use, unexpired, active account. Revokes every session, rotates the
    /// security stamp, clears the lockout state and retires all reset and verification links. Never marks an email as
    /// verified. A bad link is the one <see cref="AuthError.InvalidOrExpiredToken"/>; a rejected new password is
    /// ValidationFailed (the link is not spent).
    /// </summary>
    Task<PasswordResult> ResetPasswordAsync(ResetPasswordRequest request, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Changes the signed-in user's password after checking the current one (one Verify, lockout applies). Revokes every
    /// session including the current one. A wrong current password, or an account that cannot sign in, is the one
    /// <see cref="AuthError.GenericInvalidCredentials"/>.
    /// </summary>
    Task<PasswordResult> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class PasswordService(
    RegisterRequestValidator validator,
    IPasswordHasher hasher,
    IAuthTimingGuard timingGuard,
    ILockoutService lockout,
    IUserRepository users,
    IOneTimeTokenRepository<PasswordResetToken> resetTokens,
    IOneTimeTokenRepository<EmailVerificationToken> verificationTokens,
    IRefreshTokenRepository refreshTokens,
    IAuditLogRepository auditLog,
    IUnitOfWork unitOfWork,
    ITokenGenerator generator,
    IEmailSender emailSender,
    IClock clock,
    AccountEmailOptions options) : IPasswordService
{
    /// <summary>Longer input cannot be one of our tokens (43 characters); skip hashing and the lookup.</summary>
    private const int MaxTokenLength = 256;

    private const int MaxAttempts = 2;

    private const string NewPasswordField = "newPassword";

    public async Task<PasswordResult> ForgotPasswordAsync(ForgotPasswordRequest request, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        string email = request.Email?.Trim() ?? string.Empty;
        if (!RegisterRequestValidator.IsValidEmail(email))
        {
            // Format only: decided without the database, so it reveals nothing about which emails exist.
            return PasswordResult.Invalid(new Dictionary<string, string[]> { [AuthRequestFields.Email] = ["Email is not a valid address."] });
        }

        DateTime now = clock.UtcNow;
        User? user = await users.GetByNormalizedEmailAsync(EmailNormalizer.Normalize(email)!, cancellationToken);
        string reason = user switch
        {
            null => "unknown",
            { IsActive: false } => "inactive",
            { EmailVerified: false } => "unverified",
            _ => "sent",
        };

        EmailMessage message;
        if (reason == "sent")
        {
            GeneratedToken token = generator.Generate();
            await resetTokens.AddAsync(
                new PasswordResetToken
                {
                    UserId = user!.Id,
                    TokenHash = token.Hash,
                    CreatedUtc = now,
                    ExpiresUtc = now + options.ResetTokenLifetime,
                    RequestIp = Truncate(audit.IpAddress, 45),
                },
                cancellationToken);
            message = ResetMessage(user.Email, token.Value, now);
        }
        else
        {
            message = NoResetMessage(user?.Email ?? email, reason);
        }

        // Same database work on every path: this one save (a link row plus the audit row, or the audit row alone).
        await auditLog.AddAsync(audit.Entry(AuditEventType.PasswordResetRequested, user?.Id, now, "{\"outcome\":\"" + reason + "\"}"), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await emailSender.SendAsync(message, cancellationToken);
        return PasswordResult.Ok;
    }

    public async Task<PasswordResult> ResetPasswordAsync(ResetPasswordRequest request, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        if (string.IsNullOrEmpty(request.Token) || request.Token.Length > MaxTokenLength)
        {
            return await ResetFailedAsync(null, "malformed", audit, cancellationToken);
        }

        byte[] hash = generator.Hash(request.Token);
        DateTime now = clock.UtcNow;
        PasswordResetToken? link = await resetTokens.GetByHashAsync(hash, cancellationToken);
        string? early = link switch
        {
            null => "unknown",
            { UsedUtc: not null } => "used",
            _ when link.ExpiresUtc <= now => "expired",
            _ => null,
        };
        if (early is not null)
        {
            return await ResetFailedAsync(link?.UserId, early, audit, cancellationToken);
        }

        User? owner = await users.GetByIdAsync(link!.UserId, cancellationToken);
        if (owner is not { IsActive: true })
        {
            return await ResetFailedAsync(link.UserId, owner is null ? "unknown_user" : "inactive", audit, cancellationToken);
        }

        // Policy before spending the link, so a rejected password leaves the link usable for a second try.
        string[] policy = validator.PasswordErrors(request.NewPassword, owner.Email);
        if (policy.Length > 0)
        {
            await ResetFailedAsync(owner.Id, "policy", audit, cancellationToken);
            return PasswordResult.Invalid(new Dictionary<string, string[]> { [NewPasswordField] = policy });
        }

        string newHash = await hasher.HashAsync(request.NewPassword, cancellationToken);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                string? failure = await ResetOnceAsync(link.Id, owner.Id, newHash, audit, cancellationToken);
                if (failure is not null)
                {
                    return await ResetFailedAsync(owner.Id, failure, audit, cancellationToken);
                }

                await emailSender.SendAsync(ChangedNotice(owner.Email, clock.UtcNow), cancellationToken);
                return PasswordResult.Ok;
            }
            catch (ConcurrencyConflictException) when (attempt < MaxAttempts)
            {
                // The user row changed concurrently (e.g. a lockout write); the transaction rolled back. Retry clean.
                unitOfWork.ClearChanges();
            }
        }
    }

    public async Task<PasswordResult> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        DateTime now = clock.UtcNow;

        string[] policy = validator.PasswordErrors(request.NewPassword, user?.Email);
        if (policy.Length > 0)
        {
            await AuditAsync(AuditEventType.PasswordChangeFailed, user?.Id, "{\"reason\":\"policy\"}", audit, cancellationToken);
            return PasswordResult.Invalid(new Dictionary<string, string[]> { [NewPasswordField] = policy });
        }

        bool usable = user is { IsActive: true, EmailVerified: true, PasswordHash.Length: > 0 } && !(user.LockoutEndUtc > now);
        CredentialCheck check = await timingGuard.CheckPasswordAsync(request.CurrentPassword ?? string.Empty, user?.PasswordHash, usable, cancellationToken);
        if (check == CredentialCheck.Invalid)
        {
            // The lockout runs first: its retry clears the change tracker, so the audit row is staged after it.
            await lockout.RegisterFailureAsync(user?.Id ?? Guid.Empty, cancellationToken);
            await AuditAsync(AuditEventType.PasswordChangeFailed, user?.Id, "{\"reason\":\"" + (usable ? "wrong_password" : "unusable_account") + "\"}", audit, cancellationToken);
            return PasswordResult.Failure(AuthError.GenericInvalidCredentials);
        }

        string newHash = await hasher.HashAsync(request.NewPassword, cancellationToken);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
                User current = await users.GetByIdAsync(userId, cancellationToken) ?? throw new InvalidOperationException("The user disappeared during a password change.");
                await SetPasswordAsync(current, newHash, cancellationToken);
                await auditLog.AddAsync(audit.Entry(AuditEventType.PasswordChanged, current.Id, clock.UtcNow), cancellationToken);
                await unitOfWork.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                await emailSender.SendAsync(ChangedNotice(current.Email, clock.UtcNow), cancellationToken);
                return PasswordResult.Ok;
            }
            catch (ConcurrencyConflictException) when (attempt < MaxAttempts)
            {
                unitOfWork.ClearChanges();
            }
        }
    }

    /// <summary>One redemption in a transaction. Returns a failure reason (rolled back) or null on success.</summary>
    private async Task<string?> ResetOnceAsync(Guid linkId, Guid userId, string newHash, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        // Conditional UPDATE: of two concurrent redemptions only one can mark the link used.
        if (!await resetTokens.TryMarkUsedAsync(linkId, now, cancellationToken))
        {
            return "used";
        }

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true })
        {
            return "inactive";
        }

        // EmailVerified is deliberately left as it is: a reset proves control of the mailbox only for accounts that
        // were verified when the link was sent (links go to verified accounts only), so it never needs to change it.
        await SetPasswordAsync(user, newHash, cancellationToken);
        await auditLog.AddAsync(audit.Entry(AuditEventType.PasswordReset, user.Id, now), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return null;
    }

    /// <summary>
    /// The new password takes effect everywhere at once: new hash and security stamp, lockout cleared, every refresh
    /// family revoked (current session included), every reset link retired and every verification link retired and
    /// emptied of its pending password. Call inside a transaction; the caller saves.
    /// </summary>
    private async Task SetPasswordAsync(User user, string newHash, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        user.PasswordHash = newHash;
        user.SecurityStamp = Guid.NewGuid();
        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;
        user.LockoutLevel = 0;
        user.UpdatedUtc = now;
        await resetTokens.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        await verificationTokens.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        await refreshTokens.RevokeAllForUserAsync(user.Id, RefreshTokenRevokedReason.PasswordChange, now, cancellationToken);
    }

    private async Task<PasswordResult> ResetFailedAsync(Guid? userId, string reason, AuditContext audit, CancellationToken cancellationToken)
    {
        unitOfWork.ClearChanges();
        await AuditAsync(AuditEventType.PasswordResetFailed, userId, "{\"reason\":\"" + reason + "\"}", audit, cancellationToken);
        return PasswordResult.Failure(AuthError.InvalidOrExpiredToken);
    }

    /// <summary>Audit row in its own save; the user id is kept only when the account still exists (AuditLog FK).</summary>
    private async Task AuditAsync(AuditEventType type, Guid? userId, string detail, AuditContext audit, CancellationToken cancellationToken)
    {
        Guid? existing = userId is Guid id && await users.GetByIdAsync(id, cancellationToken) is not null ? id : null;
        await auditLog.AddAsync(audit.Entry(type, existing, clock.UtcNow, detail), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private EmailMessage ResetMessage(string email, string token, DateTime requestedUtc) => new(
        email,
        "Reset your password",
        "A password reset for this email address was requested on " + Stamp(requestedUtc) + ".\n\n"
        + "If you asked for it, choose a new password by opening this link:\n\n" + options.ResetLink(token) + "\n\n"
        + "The link works once and expires in " + (int)options.ResetTokenLifetime.TotalMinutes + " minutes. Setting a new "
        + "password signs you out everywhere.\n\n"
        + "If you did not ask for it, ignore this email; your password stays as it is.");

    private static EmailMessage NoResetMessage(string email, string reason) => new(
        email,
        "Reset your password",
        "A password reset for this email address was requested, but no link can be sent:\n\n"
        + reason switch
        {
            "unverified" => "the account for this address has not been confirmed yet. Finish signing up with the confirmation email, or sign up again to get a new one.",
            "inactive" => "the account for this address is disabled. Contact support if you think this is a mistake.",
            _ => "there is no account for this address. If you expected one, you may have signed up with another address.",
        }
        + "\n\nIf you did not ask for a reset, ignore this email.");

    private static EmailMessage ChangedNotice(string email, DateTime changedUtc) => new(
        email,
        "Your password was changed",
        "The password of your account was changed on " + Stamp(changedUtc) + ", and every session was signed out.\n\n"
        + "If this was not you, reset your password now with \"Forgot password\" and contact support.");

    private static string Stamp(DateTime utc) => utc.ToString("yyyy-MM-dd 'at' HH:mm 'UTC'", CultureInfo.InvariantCulture);

    private static string Truncate(string? value, int max) => value is null ? string.Empty : value.Length <= max ? value : value[..max];
}
