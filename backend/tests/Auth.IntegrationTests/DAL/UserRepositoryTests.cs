using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

public class UserRepositoryTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public async Task Added_user_is_found_by_id_and_by_normalized_email()
    {
        User user = TestData.User();
        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IUserRepository>().AddAsync(user, Ct);
            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
        }

        User? byId = await InScopeAsync<IUserRepository, User?>(r => r.GetByIdAsync(user.Id, Ct));
        User? byEmail = await InScopeAsync<IUserRepository, User?>(r => r.GetByNormalizedEmailAsync(user.NormalizedEmail, Ct));

        Assert.NotNull(byId);
        Assert.Equal(user.Email, byId.Email);
        Assert.NotEmpty(byId.RowVersion);
        Assert.Equal(user.Id, byEmail?.Id);
    }

    [Fact]
    public async Task Unknown_user_returns_null()
    {
        Assert.Null(await InScopeAsync<IUserRepository, User?>(r => r.GetByIdAsync(Guid.NewGuid(), Ct)));
        Assert.Null(await InScopeAsync<IUserRepository, User?>(r => r.GetByNormalizedEmailAsync("NOBODY@EXAMPLE.TEST", Ct)));
    }

    [Fact]
    public async Task Changes_to_a_tracked_user_are_saved()
    {
        User user = TestData.User();
        await SeedAsync(user);

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            User loaded = (await scope.ServiceProvider.GetRequiredService<IUserRepository>().GetByIdAsync(user.Id, Ct))!;
            loaded.FailedLoginCount = 3;
            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
        }

        User? reloaded = await InScopeAsync<IUserRepository, User?>(r => r.GetByIdAsync(user.Id, Ct));
        Assert.Equal(3, reloaded?.FailedLoginCount);
    }

    [Fact]
    public async Task Update_attaches_a_detached_user()
    {
        User user = TestData.User();
        await SeedAsync(user);
        User detached = (await InScopeAsync<IUserRepository, User?>(r => r.GetByIdAsync(user.Id, Ct)))!;
        detached.DisplayName = "Renamed";

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<IUserRepository>().Update(detached);
            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
        }

        User? reloaded = await InScopeAsync<IUserRepository, User?>(r => r.GetByIdAsync(user.Id, Ct));
        Assert.Equal("Renamed", reloaded?.DisplayName);
    }

    [Fact]
    public async Task Stale_user_update_raises_ConcurrencyConflictException()
    {
        User user = TestData.User();
        await SeedAsync(user);

        await using AsyncServiceScope first = Database.CreateScope();
        await using AsyncServiceScope second = Database.CreateScope();
        User firstCopy = (await first.ServiceProvider.GetRequiredService<IUserRepository>().GetByIdAsync(user.Id, Ct))!;
        User secondCopy = (await second.ServiceProvider.GetRequiredService<IUserRepository>().GetByIdAsync(user.Id, Ct))!;

        firstCopy.FailedLoginCount = 1;
        await first.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);

        secondCopy.FailedLoginCount = 2;
        await Assert.ThrowsAsync<ConcurrencyConflictException>(
            () => second.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct));
    }

    [Fact]
    public async Task Duplicate_normalized_email_raises_UniqueConstraintViolationException_with_the_index_name()
    {
        User original = TestData.User();
        await SeedAsync(original);
        User duplicate = TestData.User();
        duplicate.NormalizedEmail = original.NormalizedEmail;

        UniqueConstraintViolationException ex = await Assert.ThrowsAsync<UniqueConstraintViolationException>(() => SeedAsync(duplicate));

        Assert.Equal("UQ_User_NormalizedEmail", ex.ConstraintName);
    }
}
