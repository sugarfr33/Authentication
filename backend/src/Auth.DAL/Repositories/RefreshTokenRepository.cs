using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

internal sealed class RefreshTokenRepository(AuthDbContext context) : IRefreshTokenRepository
{
    public Task<RefreshToken?> GetByHashAsync(byte[] tokenHash, CancellationToken cancellationToken) =>
        context.RefreshToken.FirstOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);

    public Task<RefreshToken?> GetByHashForUpdateAsync(byte[] tokenHash, CancellationToken cancellationToken) =>
        context.RefreshToken
            .FromSql($"SELECT * FROM [auth].[RefreshToken] WITH (UPDLOCK, ROWLOCK) WHERE [TokenHash] = {tokenHash}")
            .FirstOrDefaultAsync(cancellationToken);

    public async Task AddAsync(RefreshToken token, CancellationToken cancellationToken) =>
        await context.RefreshToken.AddAsync(token, cancellationToken);

    public Task<int> RevokeFamilyAsync(Guid familyId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        context.RefreshToken
            .Where(t => t.FamilyId == familyId && t.RevokedUtc == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken);

    public Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTime revokedUtc, CancellationToken cancellationToken) =>
        context.RefreshToken
            .Where(t => t.UserId == userId && t.RevokedUtc == null)
            .ExecuteUpdateAsync(
                s => s.SetProperty(t => t.RevokedUtc, revokedUtc).SetProperty(t => t.RevokedReason, reason),
                cancellationToken);

    public async Task<IReadOnlyList<RefreshToken>> GetActiveByUserAsync(Guid userId, DateTime utcNow, CancellationToken cancellationToken) =>
        await context.RefreshToken
            .Where(t => t.UserId == userId && t.RevokedUtc == null && t.ExpiresUtc > utcNow)
            .OrderByDescending(t => t.CreatedUtc)
            .ToListAsync(cancellationToken);

    public Task<DateTime?> GetFamilyCreatedUtcAsync(Guid familyId, CancellationToken cancellationToken) =>
        context.RefreshToken
            .Where(t => t.FamilyId == familyId)
            .MinAsync(t => (DateTime?)t.CreatedUtc, cancellationToken);
}
