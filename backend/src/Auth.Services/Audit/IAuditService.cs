using Auth.Contracts;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Services.Common;

namespace Auth.Services.Audit;

/// <summary>
/// Told when a best-effort audit row could not be written. Services has no logging; the host implements this (it
/// logs the event type and the exception type only). The default does nothing.
/// </summary>
public interface IAuditFailureReporter
{
    void Report(AuditEventType type, string exceptionType);
}

internal sealed class NoAuditFailureReporter : IAuditFailureReporter
{
    public void Report(AuditEventType type, string exceptionType)
    {
    }
}

/// <summary>
/// The one way to write audit rows. Every row goes through the typed catalogue and the central detail redaction
/// (<see cref="AuditCatalogue"/>), so no password, token, hash or free text is ever persisted.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Stages the row in the current unit of work: it is saved together with the caller's change (all or nothing).
    /// Stage only after any call that may clear the change tracker (rotation, lockout retries). The user must exist.
    /// </summary>
    Task StageAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Writes the row in its own save, keeping the user id only if the account still exists (AuditLog has a foreign
    /// key to User). Throws on failure: for failure paths, where the answer does not depend on a prior success.
    /// </summary>
    Task WriteAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Like <see cref="WriteAsync"/>, for a change that has already succeeded: a failure never changes the caller's
    /// answer. It discards the tracked changes, reports the exception type to <see cref="IAuditFailureReporter"/> and
    /// returns false. Cancellation still propagates.
    /// </summary>
    Task<bool> TryWriteAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken);
}

internal sealed class AuditService(
    IAuditLogRepository auditLog,
    IUserRepository users,
    IUnitOfWork unitOfWork,
    IAuditFailureReporter failures,
    IClock clock) : IAuditService
{
    public async Task StageAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        ArgumentNullException.ThrowIfNull(context);
        await auditLog.AddAsync(context.Entry(auditEvent.Type, auditEvent.UserId, clock.UtcNow, AuditDetail.Render(auditEvent, context.ActorId)), cancellationToken);
    }

    public async Task WriteAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        ArgumentNullException.ThrowIfNull(context);
        Guid? existing = auditEvent.UserId is Guid id && await users.GetByIdAsync(id, cancellationToken) is not null ? id : null;
        await auditLog.AddAsync(context.Entry(auditEvent.Type, existing, clock.UtcNow, AuditDetail.Render(auditEvent, context.ActorId)), cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> TryWriteAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken)
    {
        try
        {
            await WriteAsync(auditEvent, context, cancellationToken);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            unitOfWork.ClearChanges();
            failures.Report(auditEvent.Type, ex.GetType().Name);
            return false;
        }
    }
}
