using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

/// <summary>
/// Set-based, batched housekeeping deletes for the retention purge. Every method is one statement that touches at
/// most <c>batch</c> rows (or, for refresh tokens, <c>batch</c> whole families) and only rows past the cutoff, so it
/// is safe to run repeatedly and from several instances at once.
/// </summary>
public interface IRetentionRepository
{
    /// <summary>
    /// Erases the pending registration payload (password hash, display name) of verification links that have expired
    /// unused. Used links were erased when used. Returns the number of rows changed.
    /// </summary>
    Task<int> ErasePendingRegistrationsAsync(DateTime utcNow, int batch, CancellationToken cancellationToken);

    /// <summary>Deletes verification links used or expired before <paramref name="cutoffUtc"/>.</summary>
    Task<int> DeleteEndedEmailVerificationTokensAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken);

    /// <summary>Deletes password reset links used or expired before <paramref name="cutoffUtc"/>.</summary>
    Task<int> DeleteEndedPasswordResetTokensAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes at most <paramref name="batch"/> token ROWS of refresh families in which every token ended (expired or
    /// revoked) before <paramref name="cutoffUtc"/>; a long family is removed over several calls. A family with any
    /// token still live, or ended after the cutoff, is never touched, so the 30-day absolute session cap (computed from a
    /// live family's first token) can never be extended. Splitting an ended family is safe: it stays ended (nothing can
    /// refresh it). First the rotation links (ReplacedByTokenId, self foreign key) of up to <paramref name="batch"/> rows
    /// of ended families are cleared, then up to <paramref name="batch"/> rows no other row points to are deleted.
    /// Returns the rows deleted (a full batch means there may be more).
    /// </summary>
    Task<int> DeleteEndedRefreshFamiliesAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken);

    /// <summary>Deletes authorization codes used or expired before <paramref name="cutoffUtc"/> (rows, batch-bounded).</summary>
    Task<int> DeleteEndedAuthorizationCodesAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes audit rows whose event type is not in <paramref name="knownEventTypes"/> (legacy or renamed events) that
    /// occurred before <paramref name="cutoffUtc"/>. Scans; bounded by <paramref name="batch"/>.
    /// </summary>
    Task<int> DeleteUnknownAuditLogAsync(IReadOnlyCollection<string> knownEventTypes, DateTime cutoffUtc, int batch, CancellationToken cancellationToken);

    /// <summary>Deletes audit rows of one event type that occurred before <paramref name="cutoffUtc"/> (uses IX_AuditLog_EventType_OccurredUtc).</summary>
    Task<int> DeleteAuditLogAsync(string eventType, DateTime cutoffUtc, int batch, CancellationToken cancellationToken);
}

internal sealed class RetentionRepository(AuthDbContext context) : IRetentionRepository
{
    public Task<int> ErasePendingRegistrationsAsync(DateTime utcNow, int batch, CancellationToken cancellationToken) =>
        context.EmailVerificationToken
            .Where(t => t.ExpiresUtc <= utcNow && (t.PendingPasswordHash != null || t.PendingDisplayName != null))
            .OrderBy(t => t.Id)
            .Take(batch)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.PendingPasswordHash, (string?)null).SetProperty(t => t.PendingDisplayName, (string?)null), cancellationToken);

    public Task<int> DeleteEndedEmailVerificationTokensAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken) =>
        context.EmailVerificationToken
            .Where(t => t.ExpiresUtc < cutoffUtc || (t.UsedUtc != null && t.UsedUtc < cutoffUtc))
            .OrderBy(t => t.Id)
            .Take(batch)
            .ExecuteDeleteAsync(cancellationToken);

    public Task<int> DeleteEndedPasswordResetTokensAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken) =>
        context.PasswordResetToken
            .Where(t => t.ExpiresUtc < cutoffUtc || (t.UsedUtc != null && t.UsedUtc < cutoffUtc))
            .OrderBy(t => t.Id)
            .Take(batch)
            .ExecuteDeleteAsync(cancellationToken);

    public async Task<int> DeleteEndedRefreshFamiliesAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken)
    {
        // A token still counts while it is neither expired nor revoked before the cutoff.
        IQueryable<Guid> endedFamilies = context.RefreshToken
            .Select(t => t.FamilyId)
            .Distinct()
            .Where(family => !context.RefreshToken.Any(t =>
                t.FamilyId == family && t.ExpiresUtc >= cutoffUtc && (t.RevokedUtc == null || t.RevokedUtc >= cutoffUtc)))
            .OrderBy(family => family)
            .Take(batch);

        // Rows of one statement are bounded by batch (lock escalation needs about 5000 locks).
        await SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => t.ReplacedByTokenId != null && endedFamilies.Contains(t.FamilyId))
            .OrderBy(t => t.Id)
            .Take(batch)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ReplacedByTokenId, (Guid?)null), cancellationToken));
        return await SqlErrors.MapDeadlockAsync(() => context.RefreshToken
            .Where(t => endedFamilies.Contains(t.FamilyId) && !context.RefreshToken.Any(other => other.ReplacedByTokenId == t.Id))
            .OrderBy(t => t.Id)
            .Take(batch)
            .ExecuteDeleteAsync(cancellationToken));
    }

    public Task<int> DeleteEndedAuthorizationCodesAsync(DateTime cutoffUtc, int batch, CancellationToken cancellationToken) =>
        context.AuthorizationCode
            .Where(c => c.ExpiresUtc < cutoffUtc || (c.UsedUtc != null && c.UsedUtc < cutoffUtc))
            .OrderBy(c => c.Id)
            .Take(batch)
            .ExecuteDeleteAsync(cancellationToken);

    public Task<int> DeleteUnknownAuditLogAsync(IReadOnlyCollection<string> knownEventTypes, DateTime cutoffUtc, int batch, CancellationToken cancellationToken) =>
        context.AuditLog
            .Where(a => !knownEventTypes.Contains(a.EventType) && a.OccurredUtc < cutoffUtc)
            .OrderBy(a => a.Id)
            .Take(batch)
            .ExecuteDeleteAsync(cancellationToken);

    public Task<int> DeleteAuditLogAsync(string eventType, DateTime cutoffUtc, int batch, CancellationToken cancellationToken) =>
        context.AuditLog
            .Where(a => a.EventType == eventType && a.OccurredUtc < cutoffUtc)
            .OrderBy(a => a.OccurredUtc)
            .Take(batch)
            .ExecuteDeleteAsync(cancellationToken);
}
