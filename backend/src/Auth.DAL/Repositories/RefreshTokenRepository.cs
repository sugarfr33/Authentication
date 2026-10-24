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

    public Task<IReadOnlyList<RefreshToken>> GetActiveByUserAsync(Guid userId, DateTime utcNow, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync<IReadOnlyList<RefreshToken>>(async () => await context.RefreshToken
            .Where(t => t.UserId == userId && t.RevokedUtc == null && t.ExpiresUtc > utcNow)
            .OrderByDescending(t => t.CreatedUtc)
            .ToListAsync(cancellationToken));

    public Task<DateTime?> GetFamilyCreatedUtcAsync(Guid familyId, CancellationToken cancellationToken) =>
        SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.FamilyId == familyId)
            .MinAsync(t => (DateTime?)t.CreatedUtc, cancellationToken));
}
