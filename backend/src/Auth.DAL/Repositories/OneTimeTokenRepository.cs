using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

/// <summary>
/// Shared implementation for the single-use token tables. They all have <c>Id</c>, <c>UserId</c> and <c>UsedUtc</c>;
/// only the hash column name differs (TokenHash or CodeHash), so it is passed in at registration.
/// </summary>
internal sealed class OneTimeTokenRepository<T>(AuthDbContext context, string hashProperty) : IOneTimeTokenRepository<T>
    where T : class
{
    private const string IdProperty = "Id";
    private const string UserIdProperty = "UserId";
    private const string UsedUtcProperty = "UsedUtc";

    public Task<T?> GetByHashAsync(byte[] hash, CancellationToken cancellationToken) =>
        context.Set<T>().FirstOrDefaultAsync(t => EF.Property<byte[]>(t, hashProperty) == hash, cancellationToken);

    public async Task AddAsync(T token, CancellationToken cancellationToken) =>
        await context.Set<T>().AddAsync(token, cancellationToken);

    public async Task<bool> TryMarkUsedAsync(Guid id, DateTime usedUtc, CancellationToken cancellationToken)
    {
        int updated = await context.Set<T>()
            .Where(t => EF.Property<Guid>(t, IdProperty) == id && EF.Property<DateTime?>(t, UsedUtcProperty) == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => EF.Property<DateTime?>(t, UsedUtcProperty), usedUtc), cancellationToken);

        return updated == 1;
    }

    public Task<int> InvalidateAllForUserAsync(Guid userId, DateTime usedUtc, CancellationToken cancellationToken) =>
        context.Set<T>()
            .Where(t => EF.Property<Guid>(t, UserIdProperty) == userId && EF.Property<DateTime?>(t, UsedUtcProperty) == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => EF.Property<DateTime?>(t, UsedUtcProperty), usedUtc), cancellationToken);
}
