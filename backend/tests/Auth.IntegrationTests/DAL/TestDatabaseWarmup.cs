using Microsoft.Data.SqlClient;

namespace Auth.IntegrationTests.DAL;

/// <summary>
/// T25: makes the database suites resilient to a cold or overloaded local SQL Server (docs/test-matrix.md, "Running the
/// database suites reliably"). Two failure modes were seen on a busy dev box: the instance answering logins only after
/// seconds (prelogin delay, error 17189 "failed to spawn a thread"), and the first burst of parallel work stalling for
/// a 30 s command timeout while SQL Server creates worker threads. The fixtures therefore
/// 1. wait for the server with retries on transient errors before their schema step, and retry that step itself;
/// 2. after the schema step, open a burst of parallel connections to the test database. This fills the process's
///    connection pool (the host under test uses the same connection string) and makes the server create the workers that
///    concurrency tests need, so the first real request does not pay for it.
/// Test code only: production behaviour is unchanged.
/// </summary>
internal static class TestDatabaseWarmup
{
    /// <summary>Connections opened at once by <see cref="WarmPoolAsync"/>: above the widest race in the suites (16).</summary>
    internal const int BurstSize = 24;

    private static readonly TimeSpan Budget = TimeSpan.FromMinutes(2);

    /// <summary>
    /// SQL error numbers treated as transient: timeout (-2), network and transport (53, 64, 121, 233, 10053, 10054,
    /// 10060), prelogin or login timeout (258), worker exhaustion (17189), deadlock victim (1205).
    /// </summary>
    private static readonly HashSet<int> TransientErrors = [-2, 53, 64, 121, 233, 258, 1205, 10053, 10054, 10060, 17189];

    /// <summary>Waits until the server answers (on master, so it works before the test database exists).</summary>
    public static Task WaitForServerAsync(string connectionString)
    {
        string master = new SqlConnectionStringBuilder(connectionString) { InitialCatalog = "master" }.ConnectionString;
        return RetryAsync(() => ExecuteAsync(master), "SQL Server did not answer");
    }

    /// <summary>Runs a schema step (for example delete then migrate) again from the start after a transient failure.</summary>
    public static Task RetryAsync(Func<Task> step, string what) => RetryCoreAsync(step, what);

    /// <summary>Opens <see cref="BurstSize"/> connections to the test database at the same time, each with retries.</summary>
    public static async Task WarmPoolAsync(string connectionString)
    {
        List<SqlConnection> open = [];
        try
        {
            Task<SqlConnection>[] opening = [.. Enumerable.Range(0, BurstSize).Select(_ => OpenWithRetryAsync(connectionString))];
            open.AddRange(await Task.WhenAll(opening));
            await Task.WhenAll(open.Select(async connection =>
            {
                await using SqlCommand command = new("SELECT 1", connection);
                await command.ExecuteScalarAsync();
            }));
        }
        finally
        {
            foreach (SqlConnection connection in open)
            {
                await connection.DisposeAsync();
            }
        }
    }

    internal static bool IsTransient(Exception exception) => exception switch
    {
        SqlException sql => sql.Errors.Cast<SqlError>().Any(e => TransientErrors.Contains(e.Number)) || TransientErrors.Contains(sql.Number),
        TimeoutException => true,

        // The pool reports a connect timeout as InvalidOperationException ("Timeout expired ... obtaining a connection").
        InvalidOperationException invalid when invalid.Message.Contains("Timeout expired", StringComparison.Ordinal) => true,
        _ => exception.InnerException is Exception inner && IsTransient(inner),
    };

    private static async Task<SqlConnection> OpenWithRetryAsync(string connectionString)
    {
        SqlConnection? opened = null;
        await RetryAsync(
            async () =>
            {
                SqlConnection connection = new(connectionString);
                try
                {
                    await connection.OpenAsync();
                    opened = connection;
                }
                catch
                {
                    await connection.DisposeAsync();
                    throw;
                }
            },
            "Could not open a warm-up connection");
        return opened!;
    }

    private static async Task ExecuteAsync(string connectionString)
    {
        await using SqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqlCommand command = new("SELECT 1", connection);
        await command.ExecuteScalarAsync();
    }

    private static async Task RetryCoreAsync(Func<Task> step, string what)
    {
        DateTime deadline = DateTime.UtcNow + Budget;
        TimeSpan delay = TimeSpan.FromMilliseconds(500);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                await step();
                return;
            }
            catch (Exception ex) when (IsTransient(ex) && DateTime.UtcNow + delay < deadline)
            {
                // A broken physical connection can sit in the pool; start the next attempt from fresh ones.
                SqlConnection.ClearAllPools();
                await Task.Delay(delay);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 5000));
            }
            catch (Exception ex) when (IsTransient(ex))
            {
                throw new TimeoutException(what + " within " + Budget.TotalMinutes + " minutes (" + attempt + " attempts). See docs/test-matrix.md.", ex);
            }
        }
    }
}
