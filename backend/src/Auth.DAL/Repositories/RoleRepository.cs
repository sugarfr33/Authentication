using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

internal sealed class RoleRepository(AuthDbContext context) : IRoleRepository
{
    public async Task<IReadOnlyList<Role>> GetForUserAsync(Guid userId, Guid? clientApplicationId, CancellationToken cancellationToken) =>
        await RolesForUser(userId, clientApplicationId)
            .OrderBy(r => r.NormalizedName)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<string>> GetPermissionCodesForUserAsync(Guid userId, Guid? clientApplicationId, CancellationToken cancellationToken) =>
        await RolesForUser(userId, clientApplicationId)
            .SelectMany(r => r.RolePermissions.Select(rp => rp.Permission.Code))
            .Distinct()
            .OrderBy(code => code)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Permission>> GetPermissionsAsync(CancellationToken cancellationToken) =>
        await context.Permission.ToListAsync(cancellationToken);

    public async Task AddPermissionAsync(Permission permission, CancellationToken cancellationToken) =>
        await context.Permission.AddAsync(permission, cancellationToken);

    public Task<Role?> GetGlobalRoleAsync(string normalizedName, CancellationToken cancellationToken) =>
        context.Role.FirstOrDefaultAsync(r => r.ClientApplicationId == null && r.NormalizedName == normalizedName, cancellationToken);

    public async Task AddRoleAsync(Role role, CancellationToken cancellationToken) =>
        await context.Role.AddAsync(role, cancellationToken);

    public async Task<IReadOnlyList<Guid>> GetPermissionIdsOfRoleAsync(Guid roleId, CancellationToken cancellationToken) =>
        await context.RolePermission.Where(rp => rp.RoleId == roleId).Select(rp => rp.PermissionId).ToListAsync(cancellationToken);

    public async Task AddRolePermissionAsync(RolePermission grant, CancellationToken cancellationToken) =>
        await context.RolePermission.AddAsync(grant, cancellationToken);

    public Task<bool> UserHasRoleAsync(Guid userId, Guid roleId, CancellationToken cancellationToken) =>
        context.UserRole.AnyAsync(ur => ur.UserId == userId && ur.RoleId == roleId, cancellationToken);

    public async Task AddUserRoleAsync(UserRole assignment, CancellationToken cancellationToken) =>
        await context.UserRole.AddAsync(assignment, cancellationToken);

    public Task<bool> AnyActiveVerifiedHolderAsync(Guid roleId, CancellationToken cancellationToken) =>
        context.UserRole.AnyAsync(ur => ur.RoleId == roleId && ur.User.IsActive && ur.User.EmailVerified, cancellationToken);

    public async Task<IReadOnlyList<Guid>> GetActiveVerifiedUsersWithoutRoleAsync(Guid roleId, int max, CancellationToken cancellationToken) =>
        await context.User
            .Where(u => u.IsActive && u.EmailVerified && !u.UserRoles.Any(ur => ur.RoleId == roleId))
            .OrderBy(u => u.Id)
            .Select(u => u.Id)
            .Take(max)
            .ToListAsync(cancellationToken);

    public Task<int> RemoveUserRoleAsync(Guid userId, Guid roleId, CancellationToken cancellationToken) =>
        context.UserRole.Where(ur => ur.UserId == userId && ur.RoleId == roleId).ExecuteDeleteAsync(cancellationToken);

    public Task<int> RemoveRolePermissionAsync(Guid roleId, Guid permissionId, CancellationToken cancellationToken) =>
        context.RolePermission.Where(rp => rp.RoleId == roleId && rp.PermissionId == permissionId).ExecuteDeleteAsync(cancellationToken);

    private IQueryable<Role> RolesForUser(Guid userId, Guid? clientApplicationId) =>
        context.Role.Where(r =>
            r.UserRoles.Any(ur => ur.UserId == userId)
            && (r.ClientApplicationId == null || r.ClientApplicationId == clientApplicationId));
}
