using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

internal sealed class AuditLogReader(AuthDbContext context) : IAuditLogReader
{
    public async Task<IReadOnlyList<AuditLog>> QueryAsync(
        Guid? userId,
        string? eventType,
        DateTime? fromUtc,
        DateTime? toUtc,
        long? beforeId,
        int take,
        CancellationToken cancellationToken)
    {
        IQueryable<AuditLog> rows = context.AuditLog.AsNoTracking();
        if (userId is Guid user)
        {
            rows = rows.Where(a => a.UserId == user);
        }

        if (eventType is { Length: > 0 } type)
        {
            rows = rows.Where(a => a.EventType == type);
        }

        if (fromUtc is DateTime from)
        {
            rows = rows.Where(a => a.OccurredUtc >= from);
        }

        if (toUtc is DateTime to)
        {
            rows = rows.Where(a => a.OccurredUtc < to);
        }

        if (beforeId is long before)
        {
            rows = rows.Where(a => a.Id < before);
        }

        return await rows.OrderByDescending(a => a.Id).Take(take).ToListAsync(cancellationToken);
    }
}
