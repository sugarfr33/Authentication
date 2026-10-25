using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Common;
using Auth.Services.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Services;

/// <summary>T11 lockout against SQL Express with a fake clock: threshold, exponential backoff, reset, concurrency.</summary>
public sealed class LockoutServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private readonly MutableClock clock = new(TestData.Now);
    private readonly ServiceProvider services;

    public LockoutServiceTests(SqlServerDatabaseFixture database)
        : base(database)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CentralAuth"] = database.ConnectionString,
                ["Auth:Issuer"] = "https://auth.example.test",
            })
            .Build();
        ServiceCollection collection = new();
        collection.AddSingleton<IClock>(clock);
        collection.AddAuthServices(configuration);
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    [Fact]
    public async Task Fifth_failure_locks_for_one_minute_and_reports_the_event()
    {
        User user = await SeedUserAsync();

        for (int i = 1; i <= 4; i++)
        {
            LockoutResult partial = await RegisterFailureAsync(user.Id);
            Assert.False(partial.IsLockedOut);
            Assert.Equal(i, partial.FailedCount);
            Assert.Null(partial.LockedOut);
        }

        LockoutResult locked = await RegisterFailureAsync(user.Id);

        Assert.True(locked.IsLockedOut);
        Assert.Equal(new AccountLockedOut(user.Id, clock.UtcNow.AddMinutes(1), 1), locked.LockedOut);
        Assert.True(await IsLockedAsync(user.Id));
        User row = await LoadAsync(user.Id);
        Assert.Equal((0, 1, clock.UtcNow.AddMinutes(1)), (row.FailedLoginCount, row.LockoutLevel, row.LockoutEndUtc));
    }

    [Fact]
    public async Task Failures_while_locked_are_not_counted_and_the_lock_expires()
    {
        User user = await SeedUserAsync();
        await FailAsync(user.Id, 5);

        LockoutResult whileLocked = await RegisterFailureAsync(user.Id);
        Assert.True(whileLocked.IsLockedOut);
        Assert.Null(whileLocked.LockedOut);
        Assert.Equal(0, (await LoadAsync(user.Id)).FailedLoginCount);

        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.False(await IsLockedAsync(user.Id));
    }

    [Fact]
    public async Task Backoff_doubles_with_each_lock_and_is_capped_at_one_hour()
    {
        User user = await SeedUserAsync();
        TimeSpan[] expected =
        [
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(4), TimeSpan.FromMinutes(8),
            TimeSpan.FromMinutes(16), TimeSpan.FromMinutes(32), TimeSpan.FromHours(1), TimeSpan.FromHours(1),
        ];

        foreach (TimeSpan duration in expected)
        {
            LockoutResult result = await FailAsync(user.Id, 5);
            Assert.Equal(clock.UtcNow + duration, result.LockoutEndUtc);
            clock.Set(result.LockoutEndUtc!.Value);
        }

        Assert.Equal(expected.Length, (await LoadAsync(user.Id)).LockoutLevel);
    }

    [Fact]
    public async Task Success_resets_the_counter_the_lock_and_the_backoff_level()
    {
        User user = await SeedUserAsync();
        await FailAsync(user.Id, 5);
        clock.Advance(TimeSpan.FromMinutes(1));
        await FailAsync(user.Id, 3);

        await InScopeAsync(s => s.ResetAsync(user.Id, Ct));

        User row = await LoadAsync(user.Id);
        Assert.Equal((0, 0, (DateTime?)null), (row.FailedLoginCount, row.LockoutLevel, row.LockoutEndUtc));
        LockoutResult next = await FailAsync(user.Id, 5);
        Assert.Equal(clock.UtcNow.AddMinutes(1), next.LockoutEndUtc);
    }

    [Fact]
    public async Task Concurrent_failures_are_never_lost()
    {
        User user = await SeedUserAsync();

        LockoutResult[] results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Task.Run(() => RegisterFailureAsync(user.Id))));

        Assert.Single(results, r => r.LockedOut is not null);
        User row = await LoadAsync(user.Id);
        Assert.Equal(1, row.LockoutLevel);
        Assert.Equal(0, row.FailedLoginCount);
        Assert.True(row.LockoutEndUtc > clock.UtcNow);
    }

    /// <summary>T11 audit LOW-4: failures spread out over more than the window never add up to a lock.</summary>
    [Fact]
    public async Task Failures_older_than_the_window_are_forgotten()
    {
        User user = await SeedUserAsync();
        await FailAsync(user.Id, 4);
        clock.Advance(TimeSpan.FromMinutes(15));

        LockoutResult afterQuiet = await RegisterFailureAsync(user.Id);
        clock.Advance(TimeSpan.FromMinutes(14));
        LockoutResult withinWindow = await FailAsync(user.Id, 3);

        Assert.Equal((false, 1), (afterQuiet.IsLockedOut, afterQuiet.FailedCount));
        Assert.Equal((false, 4), (withinWindow.IsLockedOut, withinWindow.FailedCount));
        Assert.True((await RegisterFailureAsync(user.Id)).IsLockedOut);
    }

    /// <summary>T11 audit LOW-4: the backoff level decays after a quiet day, but not within it.</summary>
    [Fact]
    public async Task The_backoff_level_decays_after_a_quiet_period()
    {
        User user = await SeedUserAsync();
        LockoutResult first = await FailAsync(user.Id, 5);
        clock.Set(first.LockoutEndUtc!.Value + TimeSpan.FromHours(23));
        LockoutResult second = await FailAsync(user.Id, 5);
        clock.Set(second.LockoutEndUtc!.Value + TimeSpan.FromHours(24));

        LockoutResult third = await FailAsync(user.Id, 5);

        Assert.Equal(2, second.LockedOut!.Level);
        Assert.Equal(1, third.LockedOut!.Level);
        Assert.Equal(clock.UtcNow.AddMinutes(1), third.LockoutEndUtc);
    }

    [Fact]
    public async Task Unknown_user_is_not_locked_and_failures_are_ignored()
    {
        Guid unknown = Guid.NewGuid();

        Assert.False(await IsLockedAsync(unknown));
        Assert.Equal(new LockoutResult(false, null, 0, null), await RegisterFailureAsync(unknown));
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private async Task<User> SeedUserAsync()
    {
        User user = TestData.User();
        await SeedAsync(user);
        return user;
    }

    private async Task<LockoutResult> FailAsync(Guid userId, int times)
    {
        LockoutResult last = new(false, null, 0, null);
        for (int i = 0; i < times; i++)
        {
            last = await RegisterFailureAsync(userId);
        }

        return last;
    }

    private Task<LockoutResult> RegisterFailureAsync(Guid userId) => InScopeAsync(s => s.RegisterFailureAsync(userId, Ct));

    private Task<bool> IsLockedAsync(Guid userId) => InScopeAsync(s => s.IsLockedOutAsync(userId, Ct));

    private async Task<T> InScopeAsync<T>(Func<ILockoutService, Task<T>> action)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<ILockoutService>());
    }

    private async Task InScopeAsync(Func<ILockoutService, Task> action)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        await action(scope.ServiceProvider.GetRequiredService<ILockoutService>());
    }

    private async Task<User> LoadAsync(Guid userId)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AuthDbContext>().User.AsNoTracking().SingleAsync(u => u.Id == userId, Ct);
    }

    private sealed class MutableClock(DateTime start) : IClock
    {
        private long ticks = start.Ticks;

        public DateTime UtcNow => new(Interlocked.Read(ref ticks), DateTimeKind.Utc);

        public void Advance(TimeSpan by) => Interlocked.Add(ref ticks, by.Ticks);

        public void Set(DateTime utc) => Interlocked.Exchange(ref ticks, utc.Ticks);
    }
}
