using System.Data;
using Auth.Contracts;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Mfa;
using Auth.Services.Security;

namespace Auth.Services.Admin;

/// <summary>What an admin account change did (T21b).</summary>
public enum AdminOutcome
{
    Changed,

    /// <summary>Already in the asked state; nothing written.</summary>
    Unchanged,

    NotFound,

    /// <summary>The acting administrator targeted their own account; refused.</summary>
    SelfLockout,

    /// <summary>The account is the last active, verified administrator; refused.</summary>
    LastAdministrator,

    /// <summary>The account kept changing concurrently; nothing changed, the caller may retry.</summary>
    Conflict,

    /// <summary>The target holds the Admin role and the actor does not; only an administrator may change an administrator.</summary>
    PrivilegeCeiling,
}

/// <summary>
/// Account administration behind /api/v1/admin/users (T21b). Reads return account fields only (no hash, secret, stamp or
/// token). Every change names the acting administrator in <see cref="AuditContext.ActorId"/>, which is audited as
/// "actor" and used for the self-lockout rules. Deactivating, reactivating or resetting the MFA of an Admin holder needs
/// an actor who is an administrator too (users.write alone is not enough). A null actor is a trusted host caller.
/// </summary>
public interface IUserAdministrationService
{
    Task<AdminUserPage> ListAsync(string? emailPrefix, int page, int pageSize, CancellationToken cancellationToken);

    Task<AdminUserDetail?> GetAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// Turns the account off and ends every session (browser and application) in one transaction, audited as
    /// UserDeactivated with the revoked count. Refuses the actor's own account and the last active, verified
    /// administrator (checked under the Admin role row lock, like a role removal).
    /// </summary>
    Task<AdminOutcome> DeactivateAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Turns the account back on and clears its lockout (failed count, lockout end and level), audited as
    /// UserReactivated. The user signs in again with their password.
    /// </summary>
    Task<AdminOutcome> ReactivateAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Admin MFA reset through <see cref="IMfaService.ResetAsync"/>: factor, recovery codes and pending enrollment gone,
    /// new security stamp, every session ended, audited as MfaDisabled (action reset, actor). Refuses the actor's own
    /// account (use the disable flow, which asks for the password and a code). Unchanged when MFA is neither on nor pending.
    /// </summary>
    Task<AdminOutcome> ResetMfaAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);

    Task<IReadOnlyList<AdminRoleInfo>> ListRolesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<AdminPermissionInfo>> ListPermissionsAsync(CancellationToken cancellationToken);
}

internal sealed class UserAdministrationService(
    IUserRepository users,
    IRoleRepository roles,
    IRefreshTokenRepository refreshTokens,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    IMfaService mfa,
    ISessionLiveness liveness,
    ISessionEndedPublisher sessionsEnded,
    IClock clock) : IUserAdministrationService
{
    /// <summary>Upper bound of the live-session count shown per account (the per-user cap is far lower).</summary>
    private const int MaxCountedSessions = 1000;

    public async Task<AdminUserPage> ListAsync(string? emailPrefix, int page, int pageSize, CancellationToken cancellationToken)
    {
        string? prefix = string.IsNullOrWhiteSpace(emailPrefix) ? null : emailPrefix.Trim().ToUpperInvariant();
        int total = await users.CountAsync(prefix, cancellationToken);
        IReadOnlyList<User> rows = await users.ListAsync(prefix, (page - 1) * pageSize, pageSize, cancellationToken);
        DateTime now = clock.UtcNow;
        return new AdminUserPage([.. rows.Select(u => Summary(u, now))], page, pageSize, total);
    }

    public async Task<AdminUserDetail?> GetAsync(Guid userId, CancellationToken cancellationToken)
    {
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return null;
        }

        DateTime now = clock.UtcNow;
        IReadOnlyList<Role> held = await roles.GetAllForUserAsync(userId, cancellationToken);
        IReadOnlyList<IRefreshSessionSummary> sessions = await refreshTokens.GetActiveSessionsAsync(userId, now, MaxCountedSessions, cancellationToken);
        return new AdminUserDetail(
            Summary(user, now),
            [.. held.Select(r => new AdminRoleReference(r.Id, r.Name, r.ClientApplication?.ClientId))],
            sessions.Count);
    }

    public async Task<AdminOutcome> DeactivateAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (audit.ActorId == userId)
        {
            return AdminOutcome.SelfLockout;
        }

        for (int attempt = 0; attempt < 2; attempt++)
        {
            unitOfWork.ClearChanges();
            try
            {
                AdminOutcome? outcome = await TryDeactivateAsync(userId, audit, cancellationToken);
                if (outcome is AdminOutcome done)
                {
                    return done;
                }
            }
            catch (ConcurrencyConflictException)
            {
                // The row changed between the read and the save (a sign-in, a lockout write): read it again once.
            }
        }

        unitOfWork.ClearChanges();
        return AdminOutcome.Conflict;
    }

    /// <summary>The outcome, or null after a lost race that is worth one more try.</summary>
    private async Task<AdminOutcome?> TryDeactivateAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            User? user = await users.GetByIdAsync(userId, cancellationToken);
            if (user is null)
            {
                return AdminOutcome.NotFound;
            }

            if (!user.IsActive)
            {
                return AdminOutcome.Unchanged;
            }

            Role? admin = await AdminRoleAsync(cancellationToken);
            bool targetIsAdmin = admin is not null && await roles.UserHasRoleAsync(userId, admin.Id, cancellationToken);
            if (targetIsAdmin && !await ActorIsAdministratorAsync(audit, admin, cancellationToken))
            {
                return AdminOutcome.PrivilegeCeiling;
            }

            if (targetIsAdmin && user.EmailVerified)
            {
                await roles.LockRoleAsync(admin!.Id, cancellationToken);
                if (await roles.CountActiveVerifiedHoldersAsync(admin.Id, userId, cancellationToken) == 0)
                {
                    return AdminOutcome.LastAdministrator;
                }
            }

            user.IsActive = false;
            user.SecurityStamp = Guid.NewGuid();
            user.UpdatedUtc = now;
            int revoked = await refreshTokens.RevokeAllForUserAsync(userId, RefreshTokenRevokedReason.Admin, now, cancellationToken);
            await audits.StageAsync(AuditEvents.UserDeactivated(userId, revoked), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        liveness.InvalidateUser(userId);
        await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.All, SessionEndCause.AdminRevoked, userId), audit, cancellationToken);
        return AdminOutcome.Changed;
    }

    public async Task<AdminOutcome> ReactivateAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            unitOfWork.ClearChanges();
            User? user = await users.GetByIdAsync(userId, cancellationToken);
            if (user is null)
            {
                return AdminOutcome.NotFound;
            }

            if (user.IsActive)
            {
                return AdminOutcome.Unchanged;
            }

            if (!await MayChangeAsync(userId, audit, cancellationToken))
            {
                return AdminOutcome.PrivilegeCeiling;
            }

            user.IsActive = true;
            user.FailedLoginCount = 0;
            user.LockoutEndUtc = null;
            user.LockoutLevel = 0;
            user.UpdatedUtc = clock.UtcNow;
            await audits.StageAsync(AuditEvents.UserReactivated(userId), audit, cancellationToken);
            try
            {
                await unitOfWork.SaveChangesAsync(cancellationToken);
                return AdminOutcome.Changed;
            }
            catch (ConcurrencyConflictException)
            {
                // Read again once.
            }
        }

        unitOfWork.ClearChanges();
        return AdminOutcome.Conflict;
    }

    public async Task<AdminOutcome> ResetMfaAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (audit.ActorId == userId)
        {
            return AdminOutcome.SelfLockout;
        }

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return AdminOutcome.NotFound;
        }

        if (!user.MfaEnabled && user.MfaSecretEncrypted is null)
        {
            return AdminOutcome.Unchanged;
        }

        if (!await MayChangeAsync(userId, audit, cancellationToken))
        {
            return AdminOutcome.PrivilegeCeiling;
        }

        try
        {
            return await mfa.ResetAsync(userId, audit, cancellationToken) ? AdminOutcome.Changed : AdminOutcome.NotFound;
        }
        catch (ConcurrencyConflictException)
        {
            unitOfWork.ClearChanges();
            return AdminOutcome.Conflict;
        }
    }

    public async Task<IReadOnlyList<AdminRoleInfo>> ListRolesAsync(CancellationToken cancellationToken) =>
        [.. (await roles.ListWithPermissionsAsync(cancellationToken)).Select(r => new AdminRoleInfo(
            r.Id,
            r.Name,
            r.ClientApplication?.ClientId,
            r.IsSystem,
            r.Description,
            [.. r.RolePermissions.Select(rp => Permission(rp.Permission)).OrderBy(p => p.Code, StringComparer.Ordinal)]))];

    public async Task<IReadOnlyList<AdminPermissionInfo>> ListPermissionsAsync(CancellationToken cancellationToken) =>
        [.. (await roles.GetPermissionsAsync(cancellationToken)).Select(Permission).OrderBy(p => p.Code, StringComparer.Ordinal)];

    private Task<Role?> AdminRoleAsync(CancellationToken cancellationToken) =>
        roles.GetGlobalRoleAsync(AuthRoles.Admin.ToUpperInvariant(), cancellationToken);

    /// <summary>A null actor (host caller) or an actor holding the Admin role.</summary>
    private async Task<bool> ActorIsAdministratorAsync(AuditContext audit, Role? admin, CancellationToken cancellationToken) =>
        audit.ActorId is not Guid actor || (admin is not null && await roles.UserHasRoleAsync(actor, admin.Id, cancellationToken));

    /// <summary>Only an administrator may change an Admin holder; anyone with users.write may change other accounts.</summary>
    private async Task<bool> MayChangeAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        Role? admin = await AdminRoleAsync(cancellationToken);
        return admin is null || !await roles.UserHasRoleAsync(userId, admin.Id, cancellationToken) || await ActorIsAdministratorAsync(audit, admin, cancellationToken);
    }

    private static AdminPermissionInfo Permission(Permission permission) => new(permission.Id, permission.Code, permission.Description);

    private static AdminUserSummary Summary(User user, DateTime now) => new(
        user.Id,
        user.Email,
        user.DisplayName,
        user.EmailVerified,
        user.IsActive,
        user.MfaEnabled,
        user.LockoutEndUtc > now,
        user.CreatedUtc,
        user.LastLoginUtc);
}
