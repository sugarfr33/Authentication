using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

/// <summary>The same behaviour is checked for each of the three single-use token tables.</summary>
public class OneTimeTokenRepositoryTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public Task PasswordResetToken_lifecycle() =>
        AssertLifecycleAsync(TestData.PasswordResetToken, t => t.Id, t => t.TokenHash, t => t.UsedUtc);

    [Fact]
    public Task EmailVerificationToken_lifecycle() =>
        AssertLifecycleAsync(TestData.EmailVerificationToken, t => t.Id, t => t.TokenHash, t => t.UsedUtc);

    [Fact]
    public Task MfaRecoveryCode_lifecycle() =>
        AssertLifecycleAsync(TestData.MfaRecoveryCode, t => t.Id, t => t.CodeHash, t => t.UsedUtc);

    /// <summary>
    /// Add and find by hash; the first TryMarkUsed wins and the second loses; InvalidateAllForUser marks only the
    /// user's unused tokens and leaves other users alone.
    /// </summary>
    private async Task AssertLifecycleAsync<T>(Func<Guid, T> create, Func<T, Guid> id, Func<T, byte[]> hash, Func<T, DateTime?> usedUtc)
        where T : class
    {
        User user = TestData.User();
        User otherUser = TestData.User();
        T redeemed = create(user.Id);
        T unused1 = create(user.Id);
        T unused2 = create(user.Id);
        T otherUsers = create(otherUser.Id);
        await SeedAsync(user, otherUser);

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            IOneTimeTokenRepository<T> repository = scope.ServiceProvider.GetRequiredService<IOneTimeTokenRepository<T>>();
            foreach (T token in new[] { redeemed, unused1, unused2, otherUsers })
            {
                await repository.AddAsync(token, Ct);
            }

            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
        }

        T? found = await InScopeAsync<IOneTimeTokenRepository<T>, T?>(r => r.GetByHashAsync([.. hash(redeemed)], Ct));
        Assert.NotNull(found);
        Assert.Equal(id(redeemed), id(found));
        Assert.Null(await InScopeAsync<IOneTimeTokenRepository<T>, T?>(r => r.GetByHashAsync(TestData.Hash(), Ct)));

        Assert.True(await InScopeAsync<IOneTimeTokenRepository<T>, bool>(r => r.TryMarkUsedAsync(id(redeemed), TestData.Now, Ct)));
        Assert.False(await InScopeAsync<IOneTimeTokenRepository<T>, bool>(r => r.TryMarkUsedAsync(id(redeemed), TestData.Now.AddMinutes(1), Ct)));
        Assert.False(await InScopeAsync<IOneTimeTokenRepository<T>, bool>(r => r.TryMarkUsedAsync(Guid.NewGuid(), TestData.Now, Ct)));

        DateTime invalidatedUtc = TestData.Now.AddMinutes(5);
        int invalidated = await InScopeAsync<IOneTimeTokenRepository<T>, int>(r => r.InvalidateAllForUserAsync(user.Id, invalidatedUtc, Ct));
        Assert.Equal(2, invalidated);

        Dictionary<Guid, DateTime?> used = await LoadUsedUtcAsync(id, usedUtc);
        Assert.Equal(TestData.Now, used[id(redeemed)]);
        Assert.Equal(invalidatedUtc, used[id(unused1)]);
        Assert.Equal(invalidatedUtc, used[id(unused2)]);
        Assert.Null(used[id(otherUsers)]);
    }

    private async Task<Dictionary<Guid, DateTime?>> LoadUsedUtcAsync<T>(Func<T, Guid> id, Func<T, DateTime?> usedUtc)
        where T : class
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        List<T> all = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Set<T>().AsNoTracking().ToListAsync(Ct);
        return all.ToDictionary(id, usedUtc);
    }
}
