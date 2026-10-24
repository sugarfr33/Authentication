using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

internal sealed class ClientApplicationRepository(AuthDbContext context) : IClientApplicationRepository
{
    public Task<ClientApplication?> GetByIdAsync(Guid id, CancellationToken cancellationToken) =>
        context.ClientApplication.FirstOrDefaultAsync(c => c.Id == id, cancellationToken);

    public Task<ClientApplication?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken) =>
        context.ClientApplication.FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);

    public async Task<IReadOnlyList<ClientApplication>> GetActiveAsync(CancellationToken cancellationToken) =>
        await context.ClientApplication
            .Where(c => c.IsActive)
            .OrderBy(c => c.ClientId)
            .ToListAsync(cancellationToken);

    public async Task AddAsync(ClientApplication application, CancellationToken cancellationToken) =>
        await context.ClientApplication.AddAsync(application, cancellationToken);

    public void Update(ClientApplication application) => context.ClientApplication.Update(application);
}
