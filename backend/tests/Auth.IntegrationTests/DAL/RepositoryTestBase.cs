using Auth.DAL;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

/// <summary>Shared helpers: each operation runs in its own DI scope (its own context), as a request would.</summary>
[Collection(SqlServerTestGroup.Name)]
public abstract class RepositoryTestBase(SqlServerDatabaseFixture database)
{
    protected SqlServerDatabaseFixture Database { get; } = database;

    protected static CancellationToken Ct => CancellationToken.None;

    /// <summary>Stages rows through the context and saves them through the unit of work, in a fresh scope.</summary>
    protected async Task SeedAsync(params object[] entities)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        context.AddRange(entities);
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
    }

    /// <summary>Runs <paramref name="action"/> with a service of type <typeparamref name="TService"/> in a fresh scope.</summary>
    protected async Task<TResult> InScopeAsync<TService, TResult>(Func<TService, Task<TResult>> action)
        where TService : notnull
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }
}
