using System.Text.Json;
using Auth.Contracts.Responses;
using Auth.DAL.Repositories;
using Auth.Entities;

namespace Auth.Services.Admin;

/// <summary>
/// Reading the audit log (T21b), for the audit.read endpoint only. Rows are returned as stored: the detail holds only
/// catalogue keys and words (central redaction at write time), but those include real failure reasons, so this read
/// model must never be reachable without the audit.read permission.
/// </summary>
public interface IAuditQueryService
{
    /// <summary>Newest first, at most <paramref name="limit"/> rows (the caller caps it).</summary>
    Task<AdminAuditPage> QueryAsync(
        Guid? userId,
        string? eventType,
        DateTime? fromUtc,
        DateTime? toUtc,
        long? before,
        int limit,
        CancellationToken cancellationToken);
}

internal sealed class AuditQueryService(IAuditLogReader reader) : IAuditQueryService
{
    public async Task<AdminAuditPage> QueryAsync(
        Guid? userId,
        string? eventType,
        DateTime? fromUtc,
        DateTime? toUtc,
        long? before,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);

        // One row more than asked tells whether another page exists.
        IReadOnlyList<AuditLog> rows = await reader.QueryAsync(userId, eventType, fromUtc, toUtc, before, limit + 1, cancellationToken);
        List<AdminAuditEntry> items = [.. rows.Take(limit).Select(Entry)];
        long? next = rows.Count > limit ? items[^1].Id : null;
        return new AdminAuditPage(items, next);
    }

    private static AdminAuditEntry Entry(AuditLog row) => new(
        row.Id,
        DateTime.SpecifyKind(row.OccurredUtc, DateTimeKind.Utc),
        row.EventType,
        row.UserId,
        row.ClientApplicationId,
        row.IpAddress,
        row.UserAgent,
        row.CorrelationId,
        ParseDetail(row.Detail));

    private static JsonElement? ParseDetail(string? detail)
    {
        if (string.IsNullOrEmpty(detail))
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(detail);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
