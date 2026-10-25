using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

/// <summary>
/// Refresh tokens are read and revoked inside the rotation transaction, where deadlocks with a sibling rotation are
/// possible, so every database call here reports a deadlock as <see cref="ConcurrencyConflictException"/>, never as a
/// raw SqlException.
/// </summary>
internal sealed class RefreshTokenRepository(AuthDbContext context) : IRefreshTokenRepository
{
    public Task<RefreshToken?> GetByHashAsync(byte[] tokenHash, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken.FirstOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken));

    public Task<RefreshToken?> GetByHashForUpdateAsync(byte[] tokenHash, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .FromSql($"SELECT * FROM [auth].[RefreshToken] WITH (UPDLOCK, ROWLOCK) WHERE [TokenHash] = {tokenHash}")
            .FirstOrDefaultAsync(cancellationToken));

    public async Task AddAsync(RefreshToken token, CancellationToken cancellationToken) =>
        await context.RefreshToken.AddAsync(token, cancellationToken);

    public Task<int> RevokeFamilyAsync(Guid familyId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.FamilyId == familyId && t.RevokedUtc == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<int> RevokeFamilyForUserAsync(Guid familyId, Guid userId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.FamilyId == familyId && t.UserId == userId && t.RevokedUtc == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.UserId == userId && t.RevokedUtc == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<int> RevokeAllForClientApplicationAsync(Guid clientApplicationId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.ClientApplicationId == clientApplicationId && t.RevokedUtc == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<int> RevokeApplicationFamiliesForUserAsync(Guid userId, Guid? clientApplicationId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.UserId == userId && t.RevokedUtc == null && t.ClientApplicationId != null
                && (clientApplicationId == null || t.ClientApplicationId == clientApplicationId))
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<int> RevokeFamiliesStartedSinceAsync(Guid userId, Guid clientApplicationId, DateTime sinceUtc, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.UserId == userId && t.ClientApplicationId == clientApplicationId && t.RevokedUtc == null
                && !context.RefreshToken.Any(f => f.FamilyId == t.FamilyId && f.CreatedUtc < sinceUtc))
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<int> RevokeAllForRoleHoldersAsync(Guid roleId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.RevokedUtc == null && context.UserRole.Any(ur => ur.RoleId == roleId && ur.UserId == t.UserId))
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken));

    public Task<IReadOnlyList<RefreshToken>> GetActiveByUserAsync(Guid userId, DateTime utcNow, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync<IReadOnlyList<RefreshToken>>(async () => await context.RefreshToken
            .Where(t => t.UserId == userId && t.RevokedUtc == null && t.ExpiresUtc > utcNow)
            .OrderByDescending(t => t.CreatedUtc)
            .ToListAsync(cancellationToken));

    public Task<IReadOnlyList<IRefreshSessionSummary>> GetActiveSessionsAsync(Guid userId, DateTime utcNow, int max, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync<IReadOnlyList<IRefreshSessionSummary>>(async () =>
        {
            // Normally one live token per family (rotation revokes the old one); keep the newest if there are more.
            List<LiveToken> live = await context.RefreshToken.AsNoTracking()
                .Where(t => t.UserId == userId && t.RevokedUtc == null && t.ExpiresUtc > utcNow)
                .OrderByDescending(t => t.CreatedUtc)
                .Select(t => new LiveToken(t.FamilyId, t.CreatedUtc, t.IpAddress, t.UserAgent, t.ClientApplicationId))
                .Take(max * 4)
                .ToListAsync(cancellationToken);
            List<LiveToken> latest = live.GroupBy(t => t.FamilyId).Select(g => g.First()).Take(max).ToList();
            List<Guid> families = latest.Select(t => t.FamilyId).ToList();

            Dictionary<Guid, DateTime> started = await context.RefreshToken.AsNoTracking()
                .Where(t => families.Contains(t.FamilyId))
                .GroupBy(t => t.FamilyId)
                .Select(g => new { FamilyId = g.Key, CreatedUtc = g.Min(t => t.CreatedUtc) })
                .ToDictionaryAsync(g => g.FamilyId, g => g.CreatedUtc, cancellationToken);

            return latest.Select(IRefreshSessionSummary (t) => new RefreshSessionSummary(t.FamilyId, started[t.FamilyId], t.CreatedUtc, t.IpAddress, t.UserAgent, t.ClientApplicationId)).ToList();
        });

    public Task<bool> IsSessionLiveAsync(Guid familyId, Guid userId, DateTime utcNow, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken.AnyAsync(
            t => t.FamilyId == familyId && t.UserId == userId && t.RevokedUtc == null && t.ExpiresUtc > utcNow && t.User.IsActive
                && (t.ClientApplicationId == null || t.ClientApplication!.IsActive),
            cancellationToken));

    public Task<bool> FamilyBelongsToUserAsync(Guid familyId, Guid userId, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken.AnyAsync(t => t.FamilyId == familyId && t.UserId == userId, cancellationToken));

    public Task<DateTime?> GetFamilyCreatedUtcAsync(Guid familyId, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.FamilyId == familyId)
            .MinAsync(t => (DateTime?)t.CreatedUtc, cancellationToken));

    private sealed record LiveToken(Guid FamilyId, DateTime CreatedUtc, string IpAddress, string UserAgent, Guid? ClientApplicationId);

    private sealed record RefreshSessionSummary(Guid FamilyId, DateTime CreatedUtc, DateTime LastUsedUtc, string IpAddress, string UserAgent, Guid? ClientApplicationId) : IRefreshSessionSummary;
}
