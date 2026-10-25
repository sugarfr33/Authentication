using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;

namespace Auth.Services.Authorization;

/// <summary>Configuration section <c>Authorization</c>.</summary>
public sealed class AuthorizationSeedOptions
{
    public const string SectionName = "Authorization";

    /// <summary>Run the seeder when the host starts (default true).</summary>
    public bool SeedOnStartup { get; set; } = true;

    /// <summary>
    /// Optional: the email of an existing, verified, active account that receives the Admin role, to create the first
    /// administrator. Used only while no active, verified user holds Admin, so it can never undo a later demotion;
    /// remove it after first use.
    /// </summary>
    public string? BootstrapAdminEmail { get; set; }
}

/// <summary>What the bootstrap-administrator step did.</summary>
public enum BootstrapAdminOutcome
{
    /// <summary>No BootstrapAdminEmail is configured.</summary>
    NotConfigured,

    /// <summary>The account received the Admin role (audited as RoleAssigned).</summary>
    Assigned,

    /// <summary>An active, verified administrator already exists: the setting was ignored and should be removed.</summary>
    AdministratorExists,

    /// <summary>No active account with a verified email matches the setting.</summary>
    AccountNotEligible,
}

/// <summary>What one seeder run added (all zero when everything already existed).</summary>
public sealed record AuthorizationSeedResult(int PermissionsAdded, int RolesAdded, int GrantsAdded, int UsersBackfilled, BootstrapAdminOutcome Bootstrap)
{
    public bool BootstrapAdminAssigned => Bootstrap == BootstrapAdminOutcome.Assigned;
}

/// <summary>
/// Creates the system permissions (<see cref="AuthPermissions.All"/>) and the global system roles Admin (every one of
/// them, always: a missing Admin grant is added back) and User (none), and gives the User role to verified, active
/// accounts that lack it (a bounded batch per run). Idempotent: it only adds what is missing and never removes rows, so
/// grants an administrator added later are kept.
/// </summary>
public interface IAuthorizationSeeder
{
    Task<AuthorizationSeedResult> SeedAsync(CancellationToken cancellationToken);
}

internal sealed class AuthorizationSeeder(
    IRoleRepository roles,
    IUserRepository users,
    IAuditLogRepository auditLog,
    IUnitOfWork unitOfWork,
    IClock clock,
    AuthorizationSeedOptions options) : IAuthorizationSeeder
{
    private const int MaxAttempts = 3;

    /// <summary>Accounts given the missing User role per run; the next run continues.</summary>
    internal const int BackfillBatch = 500;

    private static readonly Dictionary<string, string> Descriptions = new(StringComparer.Ordinal)
    {
        [AuthPermissions.UsersRead] = "Read user accounts.",
        [AuthPermissions.UsersWrite] = "Create, change and deactivate user accounts.",
        [AuthPermissions.RolesManage] = "Manage roles, permissions and role assignments.",
        [AuthPermissions.SessionsManage] = "List and revoke the sessions of any user.",
        [AuthPermissions.AuditRead] = "Read the audit log.",
        [AuthPermissions.AppsManage] = "Register and change client applications.",
    };

    public async Task<AuthorizationSeedResult> SeedAsync(CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await SeedOnceAsync(cancellationToken);
            }
            catch (UniqueConstraintViolationException) when (attempt < MaxAttempts)
            {
                // Another instance seeded the same row at the same moment: start again from what is there now.
                unitOfWork.ClearChanges();
            }
        }
    }

    private async Task<AuthorizationSeedResult> SeedOnceAsync(CancellationToken cancellationToken)
    {
        Dictionary<string, Permission> permissions = (await roles.GetPermissionsAsync(cancellationToken)).ToDictionary(p => p.Code, StringComparer.Ordinal);
        int permissionsAdded = 0;
        foreach (string code in AuthPermissions.All.Where(c => !permissions.ContainsKey(c)))
        {
            Permission permission = new() { Code = code, Description = Descriptions[code] };
            await roles.AddPermissionAsync(permission, cancellationToken);
            permissions[code] = permission;
            permissionsAdded++;
        }

        (Role admin, bool adminAdded) = await EnsureRoleAsync(AuthRoles.Admin, "Full administrative access.", cancellationToken);
        (Role user, bool userAdded) = await EnsureRoleAsync(AuthRoles.User, "Default role of every verified account.", cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        HashSet<Guid> granted = [.. await roles.GetPermissionIdsOfRoleAsync(admin.Id, cancellationToken)];
        int grantsAdded = 0;
        foreach (string code in AuthPermissions.All.Where(c => !granted.Contains(permissions[c].Id)))
        {
            await roles.AddRolePermissionAsync(new RolePermission { RoleId = admin.Id, PermissionId = permissions[code].Id }, cancellationToken);
            grantsAdded++;
        }

        BootstrapAdminOutcome bootstrap = await AssignBootstrapAdminAsync(admin, cancellationToken);
        int backfilled = await BackfillUserRoleAsync(user, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return new AuthorizationSeedResult(permissionsAdded, (adminAdded ? 1 : 0) + (userAdded ? 1 : 0), grantsAdded, backfilled, bootstrap);
    }

    /// <summary>Accounts verified while the User role was missing (seed failed or not run yet) get it now.</summary>
    private async Task<int> BackfillUserRoleAsync(Role user, CancellationToken cancellationToken)
    {
        IReadOnlyList<Guid> missing = await roles.GetActiveVerifiedUsersWithoutRoleAsync(user.Id, BackfillBatch, cancellationToken);
        DateTime now = clock.UtcNow;
        foreach (Guid userId in missing)
        {
            await roles.AddUserRoleAsync(new UserRole { UserId = userId, RoleId = user.Id, AssignedUtc = now }, cancellationToken);
            await auditLog.AddAsync(AuditContext.None.Entry(AuditEventType.RoleAssigned, userId, now, """{"role":"User","source":"backfill"}"""), cancellationToken);
        }

        return missing.Count;
    }

    private async Task<(Role Role, bool Added)> EnsureRoleAsync(string name, string description, CancellationToken cancellationToken)
    {
        Role? existing = await roles.GetGlobalRoleAsync(name.ToUpperInvariant(), cancellationToken);
        if (existing is not null)
        {
            return (existing, false);
        }

        Role role = new() { Name = name, NormalizedName = name.ToUpperInvariant(), Description = description, IsSystem = true };
        await roles.AddRoleAsync(role, cancellationToken);
        return (role, true);
    }

    /// <summary>
    /// Only the true first-administrator case: while any active, verified user holds Admin the setting is ignored, so a
    /// configuration value can never restore a role an administrator took away.
    /// </summary>
    private async Task<BootstrapAdminOutcome> AssignBootstrapAdminAsync(Role admin, CancellationToken cancellationToken)
    {
        if (EmailNormalizer.Normalize(options.BootstrapAdminEmail) is not string normalized)
        {
            return BootstrapAdminOutcome.NotConfigured;
        }

        if (await roles.AnyActiveVerifiedHolderAsync(admin.Id, cancellationToken))
        {
            return BootstrapAdminOutcome.AdministratorExists;
        }

        User? user = await users.GetByNormalizedEmailAsync(normalized, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            return BootstrapAdminOutcome.AccountNotEligible;
        }

        // The account cannot hold Admin already: it is active and verified, and no such holder exists.
        DateTime now = clock.UtcNow;
        await roles.AddUserRoleAsync(new UserRole { UserId = user.Id, RoleId = admin.Id, AssignedUtc = now }, cancellationToken);

        await auditLog.AddAsync(AuditContext.None.Entry(AuditEventType.RoleAssigned, user.Id, now, """{"role":"Admin","source":"bootstrap"}"""), cancellationToken);
        return BootstrapAdminOutcome.Assigned;
    }
}
