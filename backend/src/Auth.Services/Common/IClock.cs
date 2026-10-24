namespace Auth.Services.Common;

/// <summary>The current UTC time. Services never read DateTime.UtcNow directly, so tests can control time.</summary>
public interface IClock
{
    DateTime UtcNow { get; }
}

internal sealed class SystemClock : IClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}
