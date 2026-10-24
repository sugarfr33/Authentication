using System.Data.Common;
using Auth.DAL;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

/// <summary>
/// Creates a throwaway <c>CentralAuth_Test</c> database on local SQL Express (Windows auth) for the whole test run,
/// and drops it at the end. A leftover database from a crashed run is dropped first. The schema comes from the
/// model with EnsureCreated, because migrations arrive in T05. Override the server with CENTRALAUTH_TEST_CONNECTION.
/// </summary>
public sealed class SqlServerDatabaseFixture : IAsyncLifetime
{
    public const string ConnectionStringVariable = "CENTRALAUTH_TEST_CONNECTION";

    private const string LocalConnectionString =
        @"Server=.\SQLEXPRESS;Database=CentralAuth_Test;Trusted_Connection=True;TrustServerCertificate=True;";

    private ServiceProvider? services;

    public string ConnectionString { get; } = ResolveConnectionString();

    /// <summary>Counts every SQL command the data-access layer sends.</summary>
    public CommandCounter Commands { get; } = new();

    public IServiceProvider Services => services ?? throw new InvalidOperationException("Fixture not initialized.");

    public async Task InitializeAsync()
    {
        ServiceCollection collection = new();
        collection.AddDataAccess(ConnectionString, options => options.AddInterceptors(Commands));
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

        await using AsyncServiceScope scope = services.CreateAsyncScope();
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await context.Database.EnsureDeletedAsync();
        await context.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        if (services is null)
        {
            return;
        }

        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureDeletedAsync();
        }

        await services.DisposeAsync();
    }

    public AsyncServiceScope CreateScope() => Services.CreateAsyncScope();

    private static string ResolveConnectionString()
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable(ConnectionStringVariable);
        return string.IsNullOrWhiteSpace(fromEnvironment) ? LocalConnectionString : fromEnvironment;
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
