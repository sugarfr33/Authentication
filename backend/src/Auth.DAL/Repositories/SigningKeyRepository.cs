using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

internal sealed class SigningKeyRepository(AuthDbContext context) : ISigningKeyRepository
{
    public async Task<IReadOnlyList<SigningKey>> GetPublishableAsync(CancellationToken cancellationToken) =>
        await context.SigningKey
            .Where(k => k.Status == SigningKeyStatus.Active || k.Status == SigningKeyStatus.Retiring)
            .OrderBy(k => k.Kid)
            .ToListAsync(cancellationToken);

    public Task<SigningKey?> GetActiveAsync(CancellationToken cancellationToken) =>
        context.SigningKey
            .Where(k => k.Status == SigningKeyStatus.Active)
            .OrderByDescending(k => k.ActivatedUtc)
            .FirstOrDefaultAsync(cancellationToken);

    public Task<SigningKey?> GetByKidAsync(string kid, CancellationToken cancellationToken) =>
        context.SigningKey.FirstOrDefaultAsync(k => k.Kid == kid, cancellationToken);

    public async Task AddAsync(SigningKey key, CancellationToken cancellationToken) =>
        await context.SigningKey.AddAsync(key, cancellationToken);
}
