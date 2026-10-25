using Auth.Contracts;
using Auth.DAL.Repositories;
using Auth.Services.Audit;
using Auth.Services.Common;

namespace Auth.Services.Retention;

/// <summary>Configuration section <c>Retention</c>. Off by default: deleting data is an operator decision.</summary>
public sealed class RetentionOptions
{
    public const string SectionName = "Retention";

    private const int MaxBatch = 4000;

    /// <summary>Run the purge in the background (default false).</summary>
    public bool Enabled { get; set; }

    /// <summary>Time between runs (default 1 hour, at least 1 minute).</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Rows per statement for links and audit rows (default 1000, 1 to 4000: SQL Server escalates to a table lock at
    /// about 5000 row locks, which would block logins).
    /// </summary>
    public int BatchSize { get; set; } = 1000;

    /// <summary>Refresh token rows per statement (default 500, 1 to 4000): RefreshToken has more indexes and is hot.</summary>
    public int RefreshTokenBatchSize { get; set; } = 500;

    /// <summary>Statements per category per run (default 50), so one run is bounded; the next run continues.</summary>
    public int MaxBatchesPerRun { get; set; } = 50;

    /// <summary>Used or expired verification and reset links are kept this long after they ended (default 7 days).</summary>
    public TimeSpan OneTimeTokens { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Ended refresh families (every token expired or revoked) are kept this long (default 30 days).</summary>
    public TimeSpan RefreshFamilies { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Audit rows are kept this long (default 365 days, at least 30); also rows of unknown (legacy) event types.</summary>
    public TimeSpan AuditLog { get; set; } = TimeSpan.FromDays(365);

    /// <summary>
    /// High-volume audit rows (<see cref="AuditCatalogue.HighVolumeEventNames"/>: failed logins, refreshes, rejected
    /// refreshes and sign-ups, failed verifications) are kept this long (default 90 days, at most AuditLog).
    /// </summary>
    public TimeSpan HighVolumeAuditLog { get; set; } = TimeSpan.FromDays(90);

    public RetentionOptions Validated()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(Interval, TimeSpan.FromMinutes(1), nameof(Interval));
        ArgumentOutOfRangeException.ThrowIfLessThan(BatchSize, 1, nameof(BatchSize));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(BatchSize, MaxBatch, nameof(BatchSize));
        ArgumentOutOfRangeException.ThrowIfLessThan(RefreshTokenBatchSize, 1, nameof(RefreshTokenBatchSize));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(RefreshTokenBatchSize, MaxBatch, nameof(RefreshTokenBatchSize));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxBatchesPerRun, 1, nameof(MaxBatchesPerRun));
        ArgumentOutOfRangeException.ThrowIfLessThan(OneTimeTokens, TimeSpan.FromDays(1), nameof(OneTimeTokens));
        ArgumentOutOfRangeException.ThrowIfLessThan(RefreshFamilies, TimeSpan.FromDays(1), nameof(RefreshFamilies));
        ArgumentOutOfRangeException.ThrowIfLessThan(HighVolumeAuditLog, TimeSpan.FromDays(7), nameof(HighVolumeAuditLog));
        ArgumentOutOfRangeException.ThrowIfLessThan(AuditLog, TimeSpan.FromDays(30), nameof(AuditLog));
        ArgumentOutOfRangeException.ThrowIfLessThan(AuditLog, HighVolumeAuditLog, nameof(AuditLog));
        return this;
    }
}

/// <summary>Rows touched by one purge run, per category.</summary>
public sealed record RetentionPurgeResult(
    int PendingRegistrationsErased,
    int EmailVerificationTokensDeleted,
    int PasswordResetTokensDeleted,
    int AuthorizationCodesDeleted,
    int RefreshTokensDeleted,
    int AuditRowsDeleted)
{
    public int Total => PendingRegistrationsErased + EmailVerificationTokensDeleted + PasswordResetTokensDeleted + AuthorizationCodesDeleted + RefreshTokensDeleted + AuditRowsDeleted;
}

/// <summary>
/// One retention run: erases the pending registration payload of expired verification links at once (no retention:
/// it is a password hash), then deletes ended one-time links, whole ended refresh families and old audit rows, each
/// in bounded batches. Live data is never touched: every statement filters on an end time before the cutoff.
/// </summary>
public interface IRetentionPurge
{
    Task<RetentionPurgeResult> PurgeAsync(CancellationToken cancellationToken);
}

internal sealed class RetentionPurge(IRetentionRepository repository, IClock clock, RetentionOptions options) : IRetentionPurge
{
    private static readonly string[] KnownEventTypes = Enum.GetNames<AuditEventType>();

    public async Task<RetentionPurgeResult> PurgeAsync(CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        int erased = await RepeatAsync(batch => repository.ErasePendingRegistrationsAsync(now, batch, cancellationToken));
        int verification = await RepeatAsync(batch => repository.DeleteEndedEmailVerificationTokensAsync(now - options.OneTimeTokens, batch, cancellationToken));
        int reset = await RepeatAsync(batch => repository.DeleteEndedPasswordResetTokensAsync(now - options.OneTimeTokens, batch, cancellationToken));
        int codes = await RepeatAsync(batch => repository.DeleteEndedAuthorizationCodesAsync(now - options.OneTimeTokens, batch, cancellationToken));
        int refresh = await RepeatAsync(batch => repository.DeleteEndedRefreshFamiliesAsync(now - options.RefreshFamilies, batch, cancellationToken), options.RefreshTokenBatchSize);

        int audit = 0;
        foreach (AuditEventType type in Enum.GetValues<AuditEventType>())
        {
            TimeSpan keep = AuditCatalogue.Events[type].Volume == AuditVolume.High ? options.HighVolumeAuditLog : options.AuditLog;
            audit += await RepeatAsync(batch => repository.DeleteAuditLogAsync(type.ToString(), now - keep, batch, cancellationToken));
        }

        // Rows of event types that no longer exist (legacy or renamed) follow the normal retention.
        audit += await RepeatAsync(batch => repository.DeleteUnknownAuditLogAsync(KnownEventTypes, now - options.AuditLog, batch, cancellationToken));

        return new RetentionPurgeResult(erased, verification, reset, codes, refresh, audit);
    }

    /// <summary>Runs one batched statement until it touches less than a full batch, at most MaxBatchesPerRun times.</summary>
    private async Task<int> RepeatAsync(Func<int, Task<int>> statement, int? batchSize = null)
    {
        int batch = batchSize ?? options.BatchSize;
        int total = 0;
        for (int run = 0; run < options.MaxBatchesPerRun; run++)
        {
            int touched = await statement(batch);
            total += touched;
            if (touched < batch)
            {
                break;
            }
        }

        return total;
    }
}
