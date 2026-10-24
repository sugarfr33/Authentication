namespace Auth.Api.Security;

/// <summary>
/// Counts refused refreshes (unknown, expired, revoked or reused cookies) and logs the count as one warning at most once
/// per minute, so cookie guessing is visible without one log line per request. No cookie or token value is ever logged.
/// </summary>
internal sealed partial class RefreshRejectionLog(ILogger<RefreshRejectionLog> logger, TimeProvider time)
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private long pending;
    private long lastLoggedTicks = long.MinValue;

    public void Count()
    {
        Interlocked.Increment(ref pending);
        long now = time.GetTimestamp();
        long last = Interlocked.Read(ref lastLoggedTicks);
        if (last != long.MinValue && time.GetElapsedTime(last, now) < Interval)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref lastLoggedTicks, now, last) == last)
        {
            LogRejected(logger, Interlocked.Exchange(ref pending, 0));
        }
    }

    [LoggerMessage(EventId = 5320, Level = LogLevel.Warning, Message = "{Count} refresh request(s) refused (unknown, expired, revoked or reused session) since the last report")]
    private static partial void LogRejected(ILogger logger, long count);
}
