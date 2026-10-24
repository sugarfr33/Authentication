using System.Globalization;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Auth.Services.Tokens;

namespace Auth.Services.Accounts;

/// <summary>A started session: the tokens go to cookies only, the profile to the response body.</summary>
public sealed record SignedIn(AccessToken AccessToken, IssuedRefreshToken RefreshToken, UserProfileResponse Profile);

/// <summary>Email and password sign-in, sign-out and the signed-in profile (T13).</summary>
public interface ISignInService
{
    /// <summary>
    /// Checks the credentials and starts a session (refresh family plus an access token for the default audience).
    /// Unknown email, wrong password, unverified, inactive or locked account all give the one
    /// <see cref="AuthError.GenericInvalidCredentials"/>, after the same work: one Argon2 Verify (a dummy hash when the
    /// account cannot sign in), one lockout round trip and one audit row.
    /// </summary>
    /// <exception cref="PasswordHashingBusyException">No hashing slot freed up in time (the host answers 503).</exception>
    Task<Result<SignedIn>> LoginAsync(LoginRequest request, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Ends one session: revokes its refresh family (when known) and writes a Logout audit row.</summary>
    Task LogoutAsync(Guid userId, Guid? sessionId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Ends every session of the user: revokes all refresh families and writes a LogoutAll audit row.</summary>
    Task<int> LogoutAllAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>The profile of an active user, without secrets; <see cref="AuthError.NotFound"/> for a missing or inactive one.</summary>
    Task<Result<UserProfileResponse>> GetProfileAsync(Guid userId, CancellationToken cancellationToken);
}

internal sealed class SignInService(
    IUserRepository users,
    IRoleRepository roles,
    IAuditLogRepository auditLog,
    IUnitOfWork unitOfWork,
    IAuthTimingGuard timingGuard,
    IPasswordHasher hasher,
    ILockoutService lockout,
    IRefreshTokenService refreshTokens,
    ITokenService tokens,
    TokenOptions tokenOptions,
    IClock clock) : ISignInService
{
    public async Task<Result<SignedIn>> LoginAsync(LoginRequest request, AuditContext audit, CancellationToken cancellationToken)
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

        return Result.Success(await StartSessionAsync(user!, check == CredentialCheck.ValidNeedsRehash ? password : null, audit, cancellationToken));
    }

    public async Task LogoutAsync(Guid userId, Guid? sessionId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        int revoked = sessionId is null ? 0 : await refreshTokens.RevokeFamilyAsync(sessionId.Value, RefreshTokenRevokedReason.Logout, cancellationToken);
        await AuditAsync(AuditEventType.Logout, userId, "{\"revoked\":" + revoked.ToString(CultureInfo.InvariantCulture) + "}", audit, cancellationToken);
    }

    public async Task<int> LogoutAllAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        int revoked = await refreshTokens.RevokeAllAsync(userId, RefreshTokenRevokedReason.LogoutAll, cancellationToken);
        await AuditAsync(AuditEventType.LogoutAll, userId, "{\"revoked\":" + revoked.ToString(CultureInfo.InvariantCulture) + "}", audit, cancellationToken);
        return revoked;
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

        await auditLog.AddAsync(audit.Entry(AuditEventType.LoginFailed, user?.Id, now, "{\"reason\":\"" + reason + "\"}"), cancellationToken);
        if (result.LockedOut is AccountLockedOut locked)
        {
            string detail = "{\"until\":\"" + locked.LockoutEndUtc.ToString("O", CultureInfo.InvariantCulture)
                + "\",\"level\":" + locked.Level.ToString(CultureInfo.InvariantCulture) + "}";
            await auditLog.AddAsync(audit.Entry(AuditEventType.Lockout, locked.UserId, now, detail), cancellationToken);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private async Task<SignedIn> StartSessionAsync(User user, string? rehashPassword, AuditContext audit, CancellationToken cancellationToken)
    {
        // May clear the change tracker on a retry, so nothing is staged before it, and the user is read again after it.
        await lockout.ResetAsync(user.Id, cancellationToken);
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

        await auditLog.AddAsync(audit.Entry(AuditEventType.LoginSucceeded, userId, now), cancellationToken);
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

    private async Task AuditAsync(AuditEventType type, Guid userId, string detail, AuditContext audit, CancellationToken cancellationToken)
    {
        await auditLog.AddAsync(audit.Entry(type, userId, clock.UtcNow, detail), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }
}
