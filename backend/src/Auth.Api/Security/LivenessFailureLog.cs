namespace Auth.Api.Security;

/// <summary>
/// Counts failed live-session checks (the database did not answer) and logs them as one warning at most once per minute,
/// with the count and the latest exception type, so a database outage does not produce one log line per request.
/// </summary>
internal sealed partial class LivenessFailureLog(ILogger<LivenessFailureLog> logger, TimeProvider time)
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private long pending;
    private long lastLoggedTicks = long.MinValue;

    public void Count(string exceptionType)
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
            LogFailed(logger, Interlocked.Exchange(ref pending, 0), exceptionType);
        }
    }

    [LoggerMessage(EventId = 5330, Level = LogLevel.Warning, Message = "Live-session check failed {Count} time(s) since the last report (latest: {ExceptionType}); those requests were treated as unauthenticated")]
    private static partial void LogFailed(ILogger logger, long count, string exceptionType);
}
