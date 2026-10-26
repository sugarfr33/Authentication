namespace Auth.IntegrationTests.DAL;

/// <summary>T25: the fixture warm-up retries only what is worth retrying, and never hides a real error.</summary>
public sealed class TestDatabaseWarmupTests
{
    [Fact]
    public void Timeouts_and_pool_timeouts_are_transient_even_when_wrapped()
    {
        Assert.True(TestDatabaseWarmup.IsTransient(new TimeoutException()));
        Assert.True(TestDatabaseWarmup.IsTransient(new InvalidOperationException("Timeout expired. The timeout period elapsed prior to obtaining a connection from the pool.")));
        Assert.True(TestDatabaseWarmup.IsTransient(new InvalidOperationException("Migration failed.", new TimeoutException())));
    }

    [Fact]
    public void Other_errors_are_not_retried()
    {
        Assert.False(TestDatabaseWarmup.IsTransient(new InvalidOperationException("Refusing to create or drop database 'CentralAuth'.")));
        Assert.False(TestDatabaseWarmup.IsTransient(new ArgumentException("bad")));
    }

    [Fact]
    public async Task A_step_that_keeps_failing_for_a_real_reason_fails_at_once()
    {
        int calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => TestDatabaseWarmup.RetryAsync(
            () =>
            {
                calls++;
                throw new InvalidOperationException("not transient");
            },
            "step"));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task A_transient_failure_is_retried_until_the_step_succeeds()
    {
        int calls = 0;
        await TestDatabaseWarmup.RetryAsync(
            () =>
            {
                calls++;
                return calls < 3 ? throw new TimeoutException() : Task.CompletedTask;
            },
            "step");
        Assert.Equal(3, calls);
    }
}
