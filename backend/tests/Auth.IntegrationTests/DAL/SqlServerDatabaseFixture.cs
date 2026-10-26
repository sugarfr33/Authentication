using System.Data.Common;
using Auth.DAL;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

/// <summary>
/// Creates a throwaway database on local SQL Express (Windows auth) for the whole test run, and drops it at the end.
/// Its name is unique per run (<c>CentralAuth_run{id}_Test</c>, see <see cref="TestDatabaseNames"/>), so parallel runs
/// never collide; databases left by crashed runs more than two hours ago are dropped first. The schema comes from the
/// migrations (MigrateAsync), the same path production uses. Override the server with CENTRALAUTH_TEST_CONNECTION.
/// </summary>
public sealed class SqlServerDatabaseFixture : IAsyncLifetime
{
    public const string ConnectionStringVariable = "CENTRALAUTH_TEST_CONNECTION";

    public const string ThrowawaySuffix = "_Test";

    private const string LocalConnectionString =
        @"Server=.\SQLEXPRESS;Database=CentralAuth_Test;Trusted_Connection=True;TrustServerCertificate=True;";

    private ServiceProvider? services;

    public string ConnectionString { get; } = ResolveConnectionString();

    /// <summary>Counts every SQL command the data-access layer sends.</summary>
    public CommandCounter Commands { get; } = new();

    public IServiceProvider Services => services ?? throw new InvalidOperationException("Fixture not initialized.");

    public async Task InitializeAsync()
    {
        EnsureThrowawayDatabase(ConnectionString);
        await TestDatabaseNames.DropStaleAsync(ConnectionString, TimeSpan.FromHours(6));
        ServiceCollection collection = new();
        collection.AddDataAccess(ConnectionString, options => options.AddInterceptors(Commands));
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

        await TestDatabaseWarmup.WaitForServerAsync(ConnectionString);
        await TestDatabaseWarmup.RetryAsync(
            async () =>
            {
                await using AsyncServiceScope scope = services.CreateAsyncScope();
                AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                await context.Database.EnsureDeletedAsync();
                await context.Database.MigrateAsync();
            },
            "The test database could not be created");
        await TestDatabaseWarmup.WarmPoolAsync(ConnectionString);
    }

    public async Task DisposeAsync()
    {
        if (services is null)
        {
            return;
        }

        EnsureThrowawayDatabase(ConnectionString);

        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureDeletedAsync();
        }

        await services.DisposeAsync();
    }

    public AsyncServiceScope CreateScope() => Services.CreateAsyncScope();

    /// <summary>
    /// Safety guard: the fixture drops its database, so it refuses any target whose database name does not end with
    /// <c>_Test</c> (for example the real <c>CentralAuth</c>), including one supplied through <see cref="ConnectionStringVariable"/>.
    /// </summary>
    public static void EnsureThrowawayDatabase(string connectionString)
    {
        string database = new SqlConnectionStringBuilder(connectionString).InitialCatalog;
        if (!database.EndsWith(ThrowawaySuffix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Refusing to create or drop database '" + database + "': test databases must end with '" + ThrowawaySuffix + "'.");
        }
    }

    private static string ResolveConnectionString()
    {
        // The override chooses the server and credentials; the database name always gets this run's unique suffix.
        string? fromEnvironment = Environment.GetEnvironmentVariable(ConnectionStringVariable);
        string configured = string.IsNullOrWhiteSpace(fromEnvironment) ? LocalConnectionString : fromEnvironment;
        EnsureThrowawayDatabase(configured);
        string baseName = new SqlConnectionStringBuilder(configured).InitialCatalog;
        return TestDatabaseNames.WithUniqueDatabase(configured, baseName);
    }

    /// <summary>Records the text of each executed command so tests can assert how many statements an operation sends.</summary>
    public sealed class CommandCounter : DbCommandInterceptor
    {
        private readonly List<string> commands = [];

        public IReadOnlyList<string> Commands
        {
            get
            {
                lock (commands)
                {
                    return [.. commands];
                }
            }
        }

        public void Reset()
        {
            lock (commands)
            {
                commands.Clear();
            }
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Record(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Record(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void Record(DbCommand command)
        {
            lock (commands)
            {
                commands.Add(command.CommandText);
            }
        }
    }
}

/// <summary>All DAL integration tests share one database and run one class at a time.</summary>
[CollectionDefinition(Name)]
public sealed class SqlServerTestGroup : ICollectionFixture<SqlServerDatabaseFixture>
{
    public const string Name = "SqlServer";
}
