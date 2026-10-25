using System.Text;
using Serilog.Core;
using Serilog.Events;

namespace Auth.Api.Logging;

/// <summary>
/// A redacted copy of an exception for logging: the original type name, the message and stack trace passed through
/// <see cref="LogRedaction"/>, inner exceptions (all of them for an AggregateException) scrubbed the same way, and no
/// <see cref="Exception.Data"/> (arbitrary values a library may have attached). Never thrown, only logged.
/// </summary>
internal sealed class ScrubbedException : Exception
{
    private readonly string? stackTrace;
    private readonly IReadOnlyList<ScrubbedException> inners;

    private ScrubbedException(Exception original, IReadOnlyList<ScrubbedException> inners)
        : base(LogRedaction.Redact(original.Message), inners.Count > 0 ? inners[0] : null)
    {
        OriginalType = original.GetType().FullName ?? original.GetType().Name;
        stackTrace = original.StackTrace is string trace ? LogRedaction.Redact(trace) : null;
        this.inners = inners;
        HResult = original.HResult;
    }

    public ScrubbedException()
        : this(new InvalidOperationException(), [])
    {
    }

    public ScrubbedException(string message)
        : this(new InvalidOperationException(message), [])
    {
    }

    public ScrubbedException(string message, Exception innerException)
        : this(new InvalidOperationException(message, innerException), [From(innerException)])
    {
    }

    public string OriginalType { get; } = string.Empty;

    public override string? StackTrace => stackTrace;

    public static ScrubbedException From(Exception exception, int depth = 0)
    {
        if (exception is ScrubbedException scrubbed)
        {
            return scrubbed;
        }

        // Depth-bounded, so a pathological exception graph cannot loop or blow the stack while logging.
        IEnumerable<Exception> children = exception is AggregateException aggregate
            ? aggregate.InnerExceptions
            : exception.InnerException is Exception inner ? [inner] : [];
        List<ScrubbedException> inners = depth < 8 ? [.. children.Take(16).Select(child => From(child, depth + 1))] : [];
        return new ScrubbedException(exception, inners);
    }

    public override string ToString()
    {
        StringBuilder text = new();
        text.Append(OriginalType).Append(": ").Append(Message);
        foreach (ScrubbedException inner in inners)
        {
            text.Append(" ---> ").Append(inner.ToString()).AppendLine().Append("   --- End of inner exception stack trace ---");
        }

        if (stackTrace is not null)
        {
            text.AppendLine().Append(stackTrace);
        }

        return text.ToString();
    }
}

/// <summary>
/// Wraps every sink: an event that carries an exception reaches the sink with a <see cref="ScrubbedException"/>
/// instead (Serilog events cannot be changed in place, and the redaction enricher only sees properties).
/// </summary>
internal sealed class ExceptionScrubbingSink(ILogEventSink inner) : ILogEventSink, IDisposable
{
    public void Emit(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (logEvent.Exception is null or ScrubbedException)
        {
            inner.Emit(logEvent);
            return;
        }

        inner.Emit(new LogEvent(
            logEvent.Timestamp,
            logEvent.Level,
            ScrubbedException.From(logEvent.Exception),
            logEvent.MessageTemplate,
            logEvent.Properties.Select(p => new LogEventProperty(p.Key, p.Value)),
            logEvent.TraceId ?? default,
            logEvent.SpanId ?? default));
    }

    public void Dispose() => (inner as IDisposable)?.Dispose();
}
