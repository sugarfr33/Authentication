using Auth.Entities;

namespace Auth.DAL.Repositories;

internal sealed class AuditLogRepository(AuthDbContext context) : IAuditLogRepository
{
    public async Task AddAsync(AuditLog entry, CancellationToken cancellationToken) =>
        await context.AuditLog.AddAsync(entry, cancellationToken);
}
