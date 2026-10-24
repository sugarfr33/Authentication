using System.Data;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Auth.DAL;

/// <summary>Wraps the scoped <see cref="AuthDbContext"/> and translates EF Core failures into DAL exceptions.</summary>
internal sealed partial class UnitOfWork(AuthDbContext context) : IUnitOfWork
{
    // SQL Server: 2601 = duplicate key in a unique index, 2627 = unique/primary key constraint violation.
    private const int UniqueIndexViolation = 2601;
    private const int UniqueConstraintViolation = 2627;

    public async Task<IUnitOfWorkTransaction> BeginTransactionAsync(IsolationLevel isolationLevel, CancellationToken cancellationToken)
    {
        IDbContextTransaction transaction = await context.Database.BeginTransactionAsync(isolationLevel, cancellationToken);
        return new UnitOfWorkTransaction(transaction);
    }

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            throw new ConcurrencyConflictException("The row was changed or deleted since it was read.", ex);
        }
        catch (DbUpdateException ex) when (ex.InnerException is SqlException { Number: UniqueIndexViolation or UniqueConstraintViolation } sql)
        {
            throw new UniqueConstraintViolationException(ParseConstraintName(sql.Message), "A unique index or key was violated.", ex);
        }
        catch (DbUpdateException ex)
        {
            throw new DataAccessException("Saving changes failed.", ex);
        }
    }

    /// <summary>Extracts the index or constraint name SQL Server puts in quotes, e.g. <c>unique index 'UQ_User_NormalizedEmail'</c>.</summary>
    internal static string? ParseConstraintName(string message)
    {
        Match match = ConstraintNamePattern().Match(message);
        return match.Success ? match.Groups["name"].Value : null;
    }

    [GeneratedRegex(@"(?:unique index|constraint) '(?<name>[^']+)'", RegexOptions.CultureInvariant)]
    private static partial Regex ConstraintNamePattern();

    private sealed class UnitOfWorkTransaction(IDbContextTransaction transaction) : IUnitOfWorkTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken) => transaction.CommitAsync(cancellationToken);

        public Task RollbackAsync(CancellationToken cancellationToken) => transaction.RollbackAsync(cancellationToken);

        public ValueTask DisposeAsync() => transaction.DisposeAsync();
    }
}
