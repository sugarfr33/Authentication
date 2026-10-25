using Auth.Contracts;
using Auth.Services.Audit;

namespace Auth.Api.Logging;

/// <summary>
/// Logs best-effort audit rows that could not be written (the answer to the client was not changed): one warning per
/// minute at most, with the count since the last report and the latest event and exception type. Never a detail value.
/// </summary>
internal sealed partial class AuditFailureLog(ILogger<AuditFailureLog> logger, TimeProvider time) : IAuditFailureReporter
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private long pending;
    private long lastLoggedTicks = long.MinValue;

    public void Report(AuditEventType type, string exceptionType)
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
            LogNotWritten(logger, Interlocked.Exchange(ref pending, 0), type, exceptionType);
        }
    }

    [LoggerMessage(EventId = 5301, Level = LogLevel.Warning, Message = "{Count} audit row(s) could not be written since the last report (latest: {EventType}, {ExceptionType}); the answers were not changed")]
    private static partial void LogNotWritten(ILogger logger, long count, AuditEventType eventType, string exceptionType);
}
