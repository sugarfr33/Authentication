using System.Data;
using Auth.Contracts;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Security;

namespace Auth.Services.Authorization;

/// <summary>
/// Taking rights away. Access tokens carry the roles and permissions of the moment they were minted, so every removal
/// also revokes all refresh families of the affected users (like a password change): the live-session check then ends
/// their sessions within SessionLiveness:CacheDuration (immediately on this instance), instead of the old token keeping
/// its rights for up to one access-token lifetime. Every role or grant removal, including future admin endpoints, must
/// go through this service.
/// </summary>
public interface IRoleAssignmentService
{
    /// <summary>
    /// Takes the role from the user and ends all of the user's sessions, in one transaction, audited as RoleRemoved.
    /// False when the user did not hold the role (nothing changes).
    /// </summary>
    Task<bool> RemoveUserRoleAsync(Guid userId, Guid roleId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Takes the permission from the role and ends the sessions of every user holding the role, in one transaction,
    /// audited as RolePermissionRemoved. False when the role did not have the permission (nothing changes).
    /// </summary>
    Task<bool> RemoveRolePermissionAsync(Guid roleId, Guid permissionId, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class RoleAssignmentService(
    IRoleRepository roles,
    IRefreshTokenRepository refreshTokens,
    IAuditLogRepository auditLog,
    IUnitOfWork unitOfWork,
    ISessionLiveness liveness,
    IClock clock) : IRoleAssignmentService
{
    public async Task<bool> RemoveUserRoleAsync(Guid userId, Guid roleId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        DateTime now = clock.UtcNow;
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            if (await roles.RemoveUserRoleAsync(userId, roleId, cancellationToken) == 0)
            {
                return false;
            }

            await refreshTokens.RevokeAllForUserAsync(userId, RefreshTokenRevokedReason.Admin, now, cancellationToken);
            await auditLog.AddAsync(audit.Entry(AuditEventType.RoleRemoved, userId, now, "{\"role\":\"" + roleId.ToString("D") + "\"}"), cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        liveness.InvalidateUser(userId);
        return true;
    }

    public async Task<bool> RemoveRolePermissionAsync(Guid roleId, Guid permissionId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        DateTime now = clock.UtcNow;
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            if (await roles.RemoveRolePermissionAsync(roleId, permissionId, cancellationToken) == 0)
            {
                return false;
            }

            await refreshTokens.RevokeAllForRoleHoldersAsync(roleId, RefreshTokenRevokedReason.Admin, now, cancellationToken);
            string detail = "{\"role\":\"" + roleId.ToString("D") + "\",\"permission\":\"" + permissionId.ToString("D") + "\"}";
            await auditLog.AddAsync(audit.Entry(AuditEventType.RolePermissionRemoved, null, now, detail), cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        liveness.InvalidateAll();
        return true;
    }
}
