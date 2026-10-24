using System.Data;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
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
    /// </summary>
    /// <exception cref="PasswordHashingBusyException">No hashing slot freed up in time (the host answers 503).</exception>
    Task<RegistrationResult> RegisterAsync(RegisterRequest request, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Redeems a verification token: single use, unexpired, active account. Any failure is the one
    /// <see cref="AuthError.InvalidOrExpiredToken"/>, so the reason is not revealed.
    /// </summary>
    Task<Result> VerifyEmailAsync(string? token, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class RegistrationService(
    RegisterRequestValidator validator,
    IPasswordHasher hasher,
    IUserRepository users,
    IOneTimeTokenRepository<EmailVerificationToken> verificationTokens,
    IAuditLogRepository auditLog,
    IUnitOfWork unitOfWork,
    ITokenGenerator generator,
    IEmailSender emailSender,
    IClock clock,
    AccountEmailOptions options) : IRegistrationService
{
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
            return new RegistrationResult(errors);
        }

        string email = request.Email.Trim();
        string normalizedEmail = EmailNormalizer.Normalize(email)!;

        // Paid on every path, so a duplicate email costs the same Argon2 work as a new account. Async only: the
        // bounded gate queues without holding a thread.
        string passwordHash = await hasher.HashAsync(request.Password, cancellationToken);

        User? existing = await users.GetByNormalizedEmailAsync(normalizedEmail, cancellationToken);
        EmailMessage message = existing is null
            ? await CreateAccountAsync(email, normalizedEmail, request.DisplayName.Trim(), passwordHash, audit, cancellationToken)
                ?? await ExistingAccountAsync(await LoadAfterRaceAsync(normalizedEmail, cancellationToken), audit, cancellationToken)
            : await ExistingAccountAsync(existing, audit, cancellationToken);

        await emailSender.SendAsync(message, cancellationToken);
        return RegistrationResult.Accepted;
    }

    public async Task<Result> VerifyEmailAsync(string? token, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
        {
            return Result.Failure(AuthError.InvalidOrExpiredToken);
        }

        byte[] hash = generator.Hash(token);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await VerifyOnceAsync(hash, audit, cancellationToken);
            }
            catch (ConcurrencyConflictException) when (attempt < MaxVerifyAttempts)
            {
                // The user row changed concurrently (e.g. a lockout write); our transaction was rolled back. Retry clean.
                unitOfWork.ClearChanges();
            }
        }
    }

    /// <summary>New account plus its first verification token and the audit row, in one save. Null when a concurrent sign-up won the email.</summary>
    private async Task<EmailMessage?> CreateAccountAsync(
        string email, string normalizedEmail, string displayName, string passwordHash, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        User user = new()
        {
            Id = Guid.NewGuid(),
            Email = email,
            NormalizedEmail = normalizedEmail,
            EmailVerified = false,
            PasswordHash = passwordHash,
            DisplayName = displayName,
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        };

        await users.AddAsync(user, cancellationToken);
        string token = await AddVerificationTokenAsync(user.Id, now, cancellationToken);
        await auditLog.AddAsync(audit.Entry(AuditEventType.Registered, user.Id, now, """{"outcome":"created"}"""), cancellationToken);

        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (UniqueConstraintViolationException)
        {
            unitOfWork.ClearChanges();
            return null;
        }

        return VerificationMessage(email, token);
    }

    private async Task<User> LoadAfterRaceAsync(string normalizedEmail, CancellationToken cancellationToken) =>
        await users.GetByNormalizedEmailAsync(normalizedEmail, cancellationToken)
            ?? throw new InvalidOperationException("The email was reported as taken but no account was found.");

    /// <summary>
    /// The email is already registered. A still-unverified active account gets a fresh verification link (older links
    /// stop working), so a person who lost the first email can simply sign up again. Otherwise the owner is told that
    /// someone tried to register with their address. The caller sees the same answer either way.
    /// </summary>
    private async Task<EmailMessage> ExistingAccountAsync(User user, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        EmailMessage message;
        if (!user.EmailVerified && user.IsActive)
        {
            await verificationTokens.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
            message = VerificationMessage(user.Email, await AddVerificationTokenAsync(user.Id, now, cancellationToken));
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

        await auditLog.AddAsync(audit.Entry(AuditEventType.Registered, user.Id, now, """{"outcome":"duplicate"}"""), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return message;
    }

    private async Task<string> AddVerificationTokenAsync(Guid userId, DateTime now, CancellationToken cancellationToken)
    {
        GeneratedToken token = generator.Generate();
        await verificationTokens.AddAsync(
            new EmailVerificationToken
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                TokenHash = token.Hash,
                CreatedUtc = now,
                ExpiresUtc = now + options.VerificationTokenLifetime,
            },
            cancellationToken);
        return token.Value;
    }

    private EmailMessage VerificationMessage(string email, string token) => new(
        email,
        VerificationSubject,
        "Please confirm your email address by opening this link:\n\n" + options.VerificationLink(token) + "\n\n"
        + "The link works once and expires in " + (int)options.VerificationTokenLifetime.TotalHours + " hours. "
        + "If you did not create an account, you can ignore this email.");

    private async Task<Result> VerifyOnceAsync(byte[] hash, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        EmailVerificationToken? row = await verificationTokens.GetByHashAsync(hash, cancellationToken);
        if (row is null || row.UsedUtc is not null || row.ExpiresUtc <= now)
        {
            return Result.Failure(AuthError.InvalidOrExpiredToken);
        }

        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        // Conditional UPDATE: of two concurrent redemptions only one can mark the token used.
        if (!await verificationTokens.TryMarkUsedAsync(row.Id, now, cancellationToken))
        {
            return Result.Failure(AuthError.InvalidOrExpiredToken);
        }

        User? user = await users.GetByIdAsync(row.UserId, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return Result.Failure(AuthError.InvalidOrExpiredToken);
        }

        user.EmailVerified = true;
        user.UpdatedUtc = now;
        await verificationTokens.InvalidateAllForUserAsync(user.Id, now, cancellationToken);
        await auditLog.AddAsync(audit.Entry(AuditEventType.EmailVerified, user.Id, now), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }
}
