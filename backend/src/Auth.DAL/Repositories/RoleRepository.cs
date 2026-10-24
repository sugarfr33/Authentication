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

    private IQueryable<Role> RolesForUser(Guid userId, Guid? clientApplicationId) =>
        context.Role.Where(r =>
            r.UserRoles.Any(ur => ur.UserId == userId)
            && (r.ClientApplicationId == null || r.ClientApplicationId == clientApplicationId));
}
