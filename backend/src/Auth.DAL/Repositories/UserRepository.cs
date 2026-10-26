using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

internal sealed class UserRepository(AuthDbContext context) : IUserRepository
{
    public Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken) =>
        context.User.FirstOrDefaultAsync(u => u.Id == id, cancellationToken);

    public Task<User?> GetByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken) =>
        context.User.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, cancellationToken);

    public async Task AddAsync(User user, CancellationToken cancellationToken) =>
        await context.User.AddAsync(user, cancellationToken);

    public void Update(User user) => context.User.Update(user);

    public async Task<IReadOnlyList<User>> ListAsync(string? normalizedEmailPrefix, int skip, int take, CancellationToken cancellationToken) =>
        await Filter(normalizedEmailPrefix)
            .AsNoTracking()
            .OrderBy(u => u.NormalizedEmail)
            .ThenBy(u => u.Id)
            .Skip(skip)
            .Take(take)
            .ToListAsync(cancellationToken);

    public Task<int> CountAsync(string? normalizedEmailPrefix, CancellationToken cancellationToken) =>
        Filter(normalizedEmailPrefix).CountAsync(cancellationToken);

    private IQueryable<User> Filter(string? normalizedEmailPrefix) =>
        normalizedEmailPrefix is { Length: > 0 } prefix ? context.User.Where(u => u.NormalizedEmail.StartsWith(prefix)) : context.User;
}
