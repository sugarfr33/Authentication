using System.Data;
using System.Globalization;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Tokens;

namespace Auth.Services.Accounts;

/// <summary>Outcome of a sign-up: accepted (whether or not the email already had an account), or validation errors.</summary>
public sealed record RegistrationResult(IReadOnlyDictionary<string, string[]> ValidationErrors)
{
    public static readonly RegistrationResult Accepted = new(new Dictionary<string, string[]>());

    public bool IsAccepted => ValidationErrors.Count == 0;
}

/// <summary>Self-service sign-up and email verification (T12).</summary>
public interface IRegistrationService
{
    /// <summary>
    /// Validates the request, then always answers <see cref="RegistrationResult.Accepted"/> for a valid one, whether
    /// the email is new or already registered. Both paths do the same work: one Argon2 hash, one lookup, one save and
    /// one email (a verification link for a new or still-unverified account, an "already registered" notice otherwise).
    /// The password never becomes usable here: its hash is stored with the verification link it produced and reaches
    /// the User row only when that link is redeemed, so nobody can pre-register someone else's email with a password
    /// of their own (account pre-hijacking).
    /// </summary>
    /// <exception cref="PasswordHashingBusyException">No hashing slot freed up in time (the host answers 503).</exception>
    Task<RegistrationResult> RegisterAsync(RegisterRequest request, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Redeems a verification token: single use, unexpired, active and not yet verified account. On success the
    /// password and display name of the registration that produced THIS link become the account's, the security stamp
    /// rotates, every refresh token of the user is revoked and the user's other links are retired. Any failure is the
    /// one <see cref="AuthError.InvalidOrExpiredToken"/>, so the reason is not revealed.
    /// </summary>
    Task<Result> VerifyEmailAsync(string? token, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class RegistrationService(
    RegisterRequestValidator validator,
    IPasswordHasher hasher,
    IUserRepository users,
    IOneTimeTokenRepository<EmailVerificationToken> verificationTokens,
    IRefreshTokenRepository refreshTokens,
    IRoleRepository roles,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    ITokenGenerator generator,
    IEmailSender emailSender,
    IClock clock,
    AccountEmailOptions options) : IRegistrationService
{
    /// <summary>
    /// <c>User.PasswordHash</c> of an account that has never been verified: no usable password. It is not a PHC string,
    /// so the sign-in timing guard treats the account like an unknown one (dummy Verify, the same generic failure).
    /// </summary>
    internal const string NoUsablePassword = "";

    /// <summary>Longer input cannot be one of our tokens (43 characters); skip hashing and the lookup.</summary>
    private const int MaxTokenLength = 256;

    private const int MaxVerifyAttempts = 2;

    private const string VerificationSubject = "Confirm your email address";
    private const string AlreadyRegisteredSubject = "Your account already exists";

    public async Task<RegistrationResult> RegisterAsync(RegisterRequest request, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        IReadOnlyDictionary<string, string[]> errors = validator.Validate(request);
        if (errors.Count > 0)
        {
            // Field names only: never the submitted values. No account lookup, so it reveals nothing about existence.
            await audits.StageAsync(AuditEvents.RegistrationRejected(errors.Keys), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            return new RegistrationResult(errors);
        }

        // Paid on every path, so a duplicate email costs the same Argon2 work as a new account. Async only: the
        // bounded gate queues without holding a thread.
        string passwordHash = await hasher.HashAsync(request.Password, cancellationToken);
        Registrant registrant = new(request.Email.Trim(), request.DisplayName.Trim(), passwordHash);
        string normalizedEmail = EmailNormalizer.Normalize(registrant.Email)!;

        User? existing = await users.GetByNormalizedEmailAsync(normalizedEmail, cancellationToken);
        EmailMessage message = existing is null
            ? await CreateAccountAsync(registrant, normalizedEmail, audit, cancellationToken)
                ?? await ExistingAccountAsync(await LoadAfterRaceAsync(normalizedEmail, cancellationToken), registrant, audit, cancellationToken)
            : await ExistingAccountAsync(existing, registrant, audit, cancellationToken);

        await emailSender.SendAsync(message, cancellationToken);
        return RegistrationResult.Accepted;
    }

    public async Task<Result> VerifyEmailAsync(string? token, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
        {
            return await AuditVerifyFailureAsync(null, "malformed", audit, cancellationToken);
        }

        byte[] hash = generator.Hash(token);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                (Guid? userId, string? failure) = await VerifyOnceAsync(hash, audit, cancellationToken);
                return failure is null ? Result.Success() : await AuditVerifyFailureAsync(userId, failure, audit, cancellationToken);
            }
            catch (ConcurrencyConflictException) when (attempt < MaxVerifyAttempts)
            {
                // The user row changed concurrently (e.g. a lockout write); our transaction was rolled back. Retry clean.
                unitOfWork.ClearChanges();
            }
        }
    }

    /// <summary>Audit row for a failed redemption, in its own save after the (rolled back) transaction. Never the token.</summary>
    private async Task<Result> AuditVerifyFailureAsync(Guid? userId, string reason, AuditContext audit, CancellationToken cancellationToken)
    {
        unitOfWork.ClearChanges();
        await audits.WriteAsync(AuditEvents.EmailVerificationFailed(userId, reason), audit, cancellationToken);
        return Result.Failure(AuthError.InvalidOrExpiredToken);
    }

    /// <summary>
    /// New, unverified account WITHOUT a usable password, plus its first verification link (which holds this
    /// registration's password hash and display name) and the audit row, in one save. Null when a concurrent sign-up
    /// won the email.
    /// </summary>
    private async Task<EmailMessage?> CreateAccountAsync(Registrant registrant, string normalizedEmail, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        User user = new()
        {
            Email = registrant.Email,
            NormalizedEmail = normalizedEmail,
            EmailVerified = false,
            PasswordHash = NoUsablePassword,
            DisplayName = registrant.DisplayName,
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        };

        // AddAsync assigns the sequential Id (EF client-side generator) that the link row needs.
        await users.AddAsync(user, cancellationToken);
        string token = await AddVerificationTokenAsync(user.Id, registrant, now, cancellationToken);
        await audits.StageAsync(AuditEvents.Registered(user.Id), audit, cancellationToken);

        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (UniqueConstraintViolationException)
        {
            unitOfWork.ClearChanges();
            return null;
        }

        return VerificationMessage(registrant.Email, token, now);
    }

    private async Task<User> LoadAfterRaceAsync(string normalizedEmail, CancellationToken cancellationToken) =>
        await users.GetByNormalizedEmailAsync(normalizedEmail, cancellationToken)
            ?? throw new InvalidOperationException("The email was reported as taken but no account was found.");

    /// <summary>
    /// The email is already registered. A still-unverified active account gets one more verification link holding THIS
    /// registration's password hash; earlier links keep their own and stay valid, so a later registration never changes
    /// the password an earlier link activates. Otherwise the owner is told that someone tried to register with their
    /// address, and the hash is discarded. Nothing on the User row changes. The caller sees the same answer either way.
    /// </summary>
    private async Task<EmailMessage> ExistingAccountAsync(User user, Registrant registrant, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        EmailMessage message;
        if (!user.EmailVerified && user.IsActive)
        {
            message = VerificationMessage(user.Email, await AddVerificationTokenAsync(user.Id, registrant, now, cancellationToken), now);
        }
        else
        {
            message = new EmailMessage(
                user.Email,
                AlreadyRegisteredSubject,
                "Someone tried to create an account with this email address, but you already have one.\n\n"
                + "If it was you, sign in, or use \"Forgot password\" if you no longer know your password. "
                + "If it was not you, you can ignore this email; nothing has changed.");
        }

        await audits.StageAsync(AuditEvents.RegistrationDuplicate(user.Id), audit, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return message;
    }

    private async Task<string> AddVerificationTokenAsync(Guid userId, Registrant registrant, DateTime now, CancellationToken cancellationToken)
    {
        GeneratedToken token = generator.Generate();
        await verificationTokens.AddAsync(
            new EmailVerificationToken
            {
                UserId = userId,
                TokenHash = token.Hash,
                CreatedUtc = now,
                ExpiresUtc = now + options.VerificationTokenLifetime,
                PendingPasswordHash = registrant.PasswordHash,
                PendingDisplayName = registrant.DisplayName,
            },
            cancellationToken);
        return token.Value;
    }

    /// <summary>
    /// One template for a first and a repeated sign-up (audit MEDIUM-1 mitigation): it names the moment of the
    /// registration this link confirms and tells the reader not to open it unless they made that registration, because
    /// opening it activates the password chosen in that registration.
    /// </summary>
    private EmailMessage VerificationMessage(string email, string token, DateTime registeredUtc) => new(
        email,
        VerificationSubject,
        "A sign-up for this email address was made on "
        + registeredUtc.ToString("yyyy-MM-dd 'at' HH:mm 'UTC'", CultureInfo.InvariantCulture) + ".\n\n"
        + "If you made it, confirm your email address by opening this link:\n\n" + options.VerificationLink(token) + "\n\n"
        + "This link confirms only the sign-up made at that time and activates the password chosen in it. It works once and "
        + "expires in " + (int)options.VerificationTokenLifetime.TotalHours + " hours.\n\n"
        + "If you did not make a sign-up at that time, do NOT open the link; just ignore this email. If you received several "
        + "of these emails, open only the one that matches the sign-up you made.");

    /// <summary>One redemption attempt. Returns the failure reason for the audit (null on success); any failure rolls back.</summary>
    private async Task<(Guid? UserId, string? Failure)> VerifyOnceAsync(byte[] hash, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        EmailVerificationToken? row = await verificationTokens.GetByHashAsync(hash, cancellationToken);
        string? early = row switch
        {
            null => "unknown",
            { UsedUtc: not null } => "used",
            _ when row.ExpiresUtc <= now => "expired",
            { PendingPasswordHash: null or "" } => "no_pending_password",
            _ => null,
        };
        if (early is not null)
        {
            return (row?.UserId, early);
        }

        // Read before TryMarkUsedAsync: the same UPDATE that spends the link erases its pending payload in the row.
        string pendingPasswordHash = row!.PendingPasswordHash!;
        string? pendingDisplayName = row.PendingDisplayName;

        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        // Conditional UPDATE: of two concurrent redemptions only one can mark the token used.
        if (!await verificationTokens.TryMarkUsedAsync(row.Id, now, cancellationToken))
        {
            return (row.UserId, "used");
        }

        // A verified account is never changed by a leftover link (for example one created in a race with verification).
        User? user = await users.GetByIdAsync(row.UserId, cancellationToken);
        if (user is null || !user.IsActive || user.EmailVerified)
        {
            return (row.UserId, user is null ? "unknown_user" : user.IsActive ? "already_verified" : "inactive");
        }

        // Only now does a password become usable: the one chosen at the registration that produced this link.
        user.PasswordHash = pendingPasswordHash;
        user.DisplayName = string.IsNullOrEmpty(pendingDisplayName) ? user.DisplayName : pendingDisplayName;
        user.EmailVerified = true;
        user.SecurityStamp = Guid.NewGuid();
        user.UpdatedUtc = now;
        await verificationTokens.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        await refreshTokens.RevokeAllForUserAsync(user.Id, RefreshTokenRevokedReason.PasswordChange, now, cancellationToken);

        // Every verified account holds the default User role (when the seeder has created it).
        if (await roles.GetGlobalRoleAsync(AuthRoles.User.ToUpperInvariant(), cancellationToken) is Role defaultRole
            && !await roles.UserHasRoleAsync(user.Id, defaultRole.Id, cancellationToken))
        {
            await roles.AddUserRoleAsync(new UserRole { UserId = user.Id, RoleId = defaultRole.Id, AssignedUtc = now }, cancellationToken);
        }
        await audits.StageAsync(AuditEvents.EmailVerified(user.Id), audit, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (user.Id, null);
    }

    /// <summary>What one sign-up request chose. The hash is never written to the User row before verification.</summary>
    private sealed record Registrant(string Email, string DisplayName, string PasswordHash);
}
