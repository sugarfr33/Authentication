using System.Data;
using Auth.Contracts;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Security;

namespace Auth.Services.Authorization;

/// <summary>What a role or grant change did (T21b).</summary>
public enum RoleChangeOutcome
{
    /// <summary>The change was made and audited.</summary>
    Changed,

    /// <summary>Nothing to do: already assigned or granted, or not there to remove. Nothing written.</summary>
    Unchanged,

    /// <summary>The user, role or permission does not exist.</summary>
    NotFound,

    /// <summary>The acting administrator would take rights from their own account; refused.</summary>
    SelfLockout,

    /// <summary>Removing the Admin role would leave no active, verified administrator; refused.</summary>
    LastAdministrator,

    /// <summary>The Admin system role always holds every permission (the seeder restores them); refused.</summary>
    SystemRole,

    /// <summary>
    /// Privilege ceiling: a non-administrator may give only a role they hold, or grant only a permission they hold;
    /// refused otherwise, so roles.manage cannot be used to escalate to Admin.
    /// </summary>
    PrivilegeCeiling,
}

/// <summary>
/// Giving and taking rights; the only way to change role assignments and grants (every admin endpoint uses it).
/// Access tokens carry the roles and permissions of the moment they were minted, so every removal also revokes all
/// refresh families of the affected users (like a password change): the live-session check then ends their sessions
/// within SessionLiveness:CacheDuration (immediately on this instance), instead of the old token keeping its rights for
/// up to one access-token lifetime. Additions need no revocation: they appear at the next mint.
/// Guard rails (T21b), using <see cref="AuditContext.ActorId"/> as the acting administrator:
/// - the Admin role is never removed from the last active, verified holder; the check and the delete run under a row
///   lock on the Admin role, so two administrators demoting each other at once cannot both succeed;
/// - an administrator cannot take a role from their own account, nor a permission from a role they hold;
/// - the Admin role's permissions cannot be removed (the seeder would restore them anyway);
/// - privilege ceiling: an actor who is not an administrator may assign only a role they hold themselves and grant only
///   a permission they hold themselves (through a global role), and only an administrator may take the Admin role away.
/// A null <see cref="AuditContext.ActorId"/> means a trusted host caller (seeding, tests); the admin API always sets it.
/// </summary>
public interface IRoleAssignmentService
{
    /// <summary>Gives the role to the user, audited as RoleAssigned (source admin). Unchanged when already held.</summary>
    Task<RoleChangeOutcome> AssignUserRoleAsync(Guid userId, Guid roleId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Takes the role from the user and ends all of the user's sessions, in one transaction, audited as RoleRemoved.
    /// Unchanged when the user did not hold the role.
    /// </summary>
    Task<RoleChangeOutcome> RemoveUserRoleAsync(Guid userId, Guid roleId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Grants the permission to the role, audited as RolePermissionGranted. Unchanged when already granted.</summary>
    Task<RoleChangeOutcome> GrantRolePermissionAsync(Guid roleId, Guid permissionId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Takes the permission from the role and ends the sessions of every user holding the role, in one transaction,
    /// audited as RolePermissionRemoved. Unchanged when the role did not have the permission.
    /// </summary>
    Task<RoleChangeOutcome> RemoveRolePermissionAsync(Guid roleId, Guid permissionId, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class RoleAssignmentService(
    IRoleRepository roles,
    IUserRepository users,
    IRefreshTokenRepository refreshTokens,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    ISessionLiveness liveness,
    ISessionEndedPublisher sessionsEnded,
    IClock clock) : IRoleAssignmentService
{
    internal const string AdminSource = "admin";

    public async Task<RoleChangeOutcome> AssignUserRoleAsync(Guid userId, Guid roleId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (await users.GetByIdAsync(userId, cancellationToken) is null || await roles.GetByIdAsync(roleId, cancellationToken) is null)
        {
            return RoleChangeOutcome.NotFound;
        }

        if (await roles.UserHasRoleAsync(userId, roleId, cancellationToken))
        {
            return RoleChangeOutcome.Unchanged;
        }

        if (audit.ActorId is Guid actor && !await IsAdministratorAsync(actor, cancellationToken) && !await roles.UserHasRoleAsync(actor, roleId, cancellationToken))
        {
            return RoleChangeOutcome.PrivilegeCeiling;
        }

        await roles.AddUserRoleAsync(new UserRole { UserId = userId, RoleId = roleId, AssignedUtc = clock.UtcNow }, cancellationToken);
        await audits.StageAsync(AuditEvents.RoleAssigned(userId, roleId, AdminSource), audit, cancellationToken);
        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (UniqueConstraintViolationException)
        {
            // A concurrent assignment of the same role won: the user holds it, which is what was asked.
            unitOfWork.ClearChanges();
            return RoleChangeOutcome.Unchanged;
        }

        return RoleChangeOutcome.Changed;
    }

    public async Task<RoleChangeOutcome> RemoveUserRoleAsync(Guid userId, Guid roleId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        if (audit.ActorId == userId)
        {
            return RoleChangeOutcome.SelfLockout;
        }

        DateTime now = clock.UtcNow;
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            Role? role = await roles.GetByIdAsync(roleId, cancellationToken);
            if (role is not null && IsAdminRole(role))
            {
                // Serialises every "how many administrators are left" decision until this transaction ends.
                // Only an active, verified holder counts as an administrator: removing the role from a stale
                // (inactive or unverified) account never lowers the count, so it is allowed.
                await roles.LockRoleAsync(roleId, cancellationToken);
                if (audit.ActorId is Guid actor && !await roles.UserHasRoleAsync(actor, roleId, cancellationToken))
                {
                    // Only an administrator may demote an administrator (read under the lock, after any concurrent demotion).
                    return RoleChangeOutcome.PrivilegeCeiling;
                }

                if (await users.GetByIdAsync(userId, cancellationToken) is { IsActive: true, EmailVerified: true }
                    && await roles.UserHasRoleAsync(userId, roleId, cancellationToken)
                    && await roles.CountActiveVerifiedHoldersAsync(roleId, userId, cancellationToken) == 0)
                {
                    return RoleChangeOutcome.LastAdministrator;
                }
            }

            if (await roles.RemoveUserRoleAsync(userId, roleId, cancellationToken) == 0)
            {
                return RoleChangeOutcome.Unchanged;
            }

            await refreshTokens.RevokeAllForUserAsync(userId, RefreshTokenRevokedReason.Admin, now, cancellationToken);
            await audits.StageAsync(AuditEvents.RoleRemoved(userId, roleId), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        liveness.InvalidateUser(userId);
        await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.All, SessionEndCause.AdminRevoked, userId), audit, cancellationToken);
        return RoleChangeOutcome.Changed;
    }

    public async Task<RoleChangeOutcome> GrantRolePermissionAsync(Guid roleId, Guid permissionId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        Permission? permission = await roles.GetPermissionByIdAsync(permissionId, cancellationToken);
        if (await roles.GetByIdAsync(roleId, cancellationToken) is null || permission is null)
        {
            return RoleChangeOutcome.NotFound;
        }

        if (await roles.RoleHasPermissionAsync(roleId, permissionId, cancellationToken))
        {
            return RoleChangeOutcome.Unchanged;
        }

        if (audit.ActorId is Guid actor
            && !await IsAdministratorAsync(actor, cancellationToken)
            && !(await roles.GetPermissionCodesForUserAsync(actor, null, cancellationToken)).Contains(permission.Code, StringComparer.Ordinal))
        {
            return RoleChangeOutcome.PrivilegeCeiling;
        }

        await roles.AddRolePermissionAsync(new RolePermission { RoleId = roleId, PermissionId = permissionId }, cancellationToken);
        await audits.StageAsync(AuditEvents.RolePermissionGranted(roleId, permissionId), audit, cancellationToken);
        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (UniqueConstraintViolationException)
        {
            unitOfWork.ClearChanges();
            return RoleChangeOutcome.Unchanged;
        }

        return RoleChangeOutcome.Changed;
    }

    public async Task<RoleChangeOutcome> RemoveRolePermissionAsync(Guid roleId, Guid permissionId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        Role? role = await roles.GetByIdAsync(roleId, cancellationToken);
        if (role is not null && IsAdminRole(role))
        {
            return RoleChangeOutcome.SystemRole;
        }

        if (audit.ActorId is Guid actor && await roles.UserHasRoleAsync(actor, roleId, cancellationToken))
        {
            return RoleChangeOutcome.SelfLockout;
        }

        DateTime now = clock.UtcNow;
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            if (await roles.RemoveRolePermissionAsync(roleId, permissionId, cancellationToken) == 0)
            {
                return RoleChangeOutcome.Unchanged;
            }

            await refreshTokens.RevokeAllForRoleHoldersAsync(roleId, RefreshTokenRevokedReason.Admin, now, cancellationToken);
            await audits.StageAsync(AuditEvents.RolePermissionRemoved(roleId, permissionId), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        liveness.InvalidateAll();
        await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.All, SessionEndCause.AdminRevoked, null, RoleId: roleId), audit, cancellationToken);
        return RoleChangeOutcome.Changed;
    }

    /// <summary>Whether the user holds the global Admin role (read from the database, not from the token).</summary>
    private async Task<bool> IsAdministratorAsync(Guid userId, CancellationToken cancellationToken) =>
        await roles.GetGlobalRoleAsync(AuthRoles.Admin.ToUpperInvariant(), cancellationToken) is Role admin
        && await roles.UserHasRoleAsync(userId, admin.Id, cancellationToken);

    internal static bool IsAdminRole(Role role) =>
        role.IsSystem && role.ClientApplicationId is null && string.Equals(role.NormalizedName, AuthRoles.Admin, StringComparison.OrdinalIgnoreCase);
}
