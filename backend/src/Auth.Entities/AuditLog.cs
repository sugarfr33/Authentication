namespace Auth.Entities;

/// <summary>Append-only security event. <see cref="Detail"/> is redacted JSON and never holds secrets. Table <c>auth.AuditLog</c>.</summary>
public class AuditLog
{
    public long Id { get; set; }

    public DateTime OccurredUtc { get; set; }

    public string EventType { get; set; } = string.Empty;

    public Guid? UserId { get; set; }

    public Guid? ClientApplicationId { get; set; }

    public string? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    public string? Detail { get; set; }

    public string? CorrelationId { get; set; }
}
