using Auth.Contracts;
using Auth.Entities;

namespace Auth.Services.Common;

/// <summary>Who made the request, for audit rows. Values are truncated to the AuditLog column sizes.</summary>
public sealed record AuditContext(string? IpAddress, string? UserAgent, string? CorrelationId)
{
    public static readonly AuditContext None = new(null, null, null);

    /// <summary>A new audit row. <paramref name="detail"/> is short JSON without secrets, tokens or passwords.</summary>
    internal AuditLog Entry(AuditEventType type, Guid? userId, DateTime occurredUtc, string? detail = null) => new()
    {
        OccurredUtc = occurredUtc,
        EventType = type.ToString(),
        UserId = userId,
        IpAddress = Truncate(IpAddress, 45),
        UserAgent = Truncate(UserAgent, 512),
        CorrelationId = Truncate(CorrelationId, 64),
        Detail = detail,
    };

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
