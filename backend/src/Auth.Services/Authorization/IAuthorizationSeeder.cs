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
    /// Optional: the email of an existing, verified, active account that receives the Admin role when the seeder runs,
    /// to create the first administrator. Leave empty once an administrator exists.
    /// </summary>
    public string? BootstrapAdminEmail { get; set; }
}

/// <summary>What one seeder run added (all zero when everything already existed).</summary>
public sealed record AuthorizationSeedResult(int PermissionsAdded, int RolesAdded, int GrantsAdded, bool BootstrapAdminAssigned);

/// <summary>
/// Creates the system permissions (<see cref="AuthPermissions.All"/>) and the global system roles Admin (every one of
/// them) and User (none). Idempotent: it only adds what is missing and never removes or changes existing rows, so
/// grants an administrator added later are kept.
/// </summary>
public interface IAuthorizationSeeder
{
    Task<AuthorizationSeedResult> SeedAsync(CancellationToken cancellationToken);
}

internal sealed class AuthorizationSeeder(
    IRoleRepository roles,
    IUserRepository users,
    IUnitOfWork unitOfWork,
    IClock clock,
    AuthorizationSeedOptions options) : IAuthorizationSeeder
{
    private const int MaxAttempts = 3;

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
        (_, bool userAdded) = await EnsureRoleAsync(AuthRoles.User, "Default role of every verified account.", cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        HashSet<Guid> granted = [.. await roles.GetPermissionIdsOfRoleAsync(admin.Id, cancellationToken)];
        int grantsAdded = 0;
        foreach (string code in AuthPermissions.All.Where(c => !granted.Contains(permissions[c].Id)))
        {
            await roles.AddRolePermissionAsync(new RolePermission { RoleId = admin.Id, PermissionId = permissions[code].Id }, cancellationToken);
            grantsAdded++;
        }

        bool bootstrapped = await AssignBootstrapAdminAsync(admin, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return new AuthorizationSeedResult(permissionsAdded, (adminAdded ? 1 : 0) + (userAdded ? 1 : 0), grantsAdded, bootstrapped);
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

    private async Task<bool> AssignBootstrapAdminAsync(Role admin, CancellationToken cancellationToken)
    {
        if (EmailNormalizer.Normalize(options.BootstrapAdminEmail) is not string normalized)
        {
            return false;
        }

        User? user = await users.GetByNormalizedEmailAsync(normalized, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true } || await roles.UserHasRoleAsync(user.Id, admin.Id, cancellationToken))
        {
            return false;
        }

        await roles.AddUserRoleAsync(new UserRole { UserId = user.Id, RoleId = admin.Id, AssignedUtc = clock.UtcNow }, cancellationToken);
        return true;
    }
}
