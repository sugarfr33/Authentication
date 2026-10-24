using System.Data;

namespace Auth.DAL;

/// <summary>
/// Saves the changes of every repository in the current scope; they all share one context.
/// A single <see cref="SaveChangesAsync"/> is atomic on its own. Use <see cref="BeginTransactionAsync"/> when several saves,
/// or the set-based revoke and mark-used methods, must commit or roll back together.
/// </summary>
public interface IUnitOfWork
{
    Task<IUnitOfWorkTransaction> BeginTransactionAsync(IsolationLevel isolationLevel, CancellationToken cancellationToken);

    /// <summary>Saves tracked changes.</summary>
    /// <exception cref="ConcurrencyConflictException">A RowVersion check failed.</exception>
    /// <exception cref="UniqueConstraintViolationException">A unique index or key was violated.</exception>
    /// <exception cref="DataAccessException">Any other database failure while saving.</exception>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken);
}

/// <summary>An open database transaction. Disposing it without <see cref="CommitAsync"/> rolls it back.</summary>
public interface IUnitOfWorkTransaction : IAsyncDisposable
{
    Task CommitAsync(CancellationToken cancellationToken);

    Task RollbackAsync(CancellationToken cancellationToken);
}
