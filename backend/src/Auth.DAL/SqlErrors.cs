using Microsoft.Data.SqlClient;

namespace Auth.DAL;

/// <summary>SQL Server error classification shared by the unit of work and the repositories.</summary>
internal static class SqlErrors
{
    /// <summary>Chosen as deadlock victim; the server has already rolled the transaction back.</summary>
    public const int DeadlockVictim = 1205;

    /// <summary>
    /// The SqlException anywhere in the chain. EF wraps a deadlock in an InvalidOperationException ("transient failure")
    /// around the DbUpdateException or the query exception, so checking only the direct inner exception misses it.
    /// </summary>
    public static SqlException? Find(Exception? exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is SqlException sql)
            {
                return sql;
            }
        }

        return null;
    }

    public static bool IsDeadlock(Exception exception) => Find(exception) is { Number: DeadlockVictim };

    /// <summary>Runs a query or set-based statement, reporting a deadlock as <see cref="ConcurrencyConflictException"/>.</summary>
    public static async Task<T> MapDeadlockAsync<T>(Func<Task<T>> operation)
    {
        try
        {
            return await operation();
        }
        catch (Exception ex) when (IsDeadlock(ex))
        {
            throw new ConcurrencyConflictException("The statement lost a concurrent update (deadlock victim) and was rolled back.", ex);
        }
    }
}
