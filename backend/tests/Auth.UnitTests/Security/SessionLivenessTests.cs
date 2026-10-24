using Auth.Services.Common;
using Auth.Services.Security;

namespace Auth.UnitTests.Security;

/// <summary>T16 prerequisite 2: the live-session cache is short, bounded and never shared between users.</summary>
public class SessionLivenessTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;
    private readonly Guid alice = Guid.NewGuid();
    private readonly Guid bob = Guid.NewGuid();
    private readonly Guid session = Guid.NewGuid();
    private readonly FakeClock clock = new();

    [Fact]
    public async Task A_result_is_reused_only_within_the_cache_duration()
    {
        int lookups = 0;
        bool live = true;
        SessionLiveness liveness = New((_, _, _, _) =>
        {
            lookups++;
            return Task.FromResult(live);
        });

        Assert.True(await liveness.IsLiveAsync(alice, session, Ct));
        live = false;
        Assert.True(await liveness.IsLiveAsync(alice, session, Ct));
        clock.Now += TimeSpan.FromSeconds(5);
        Assert.False(await liveness.IsLiveAsync(alice, session, Ct));

        Assert.Equal(2, lookups);
    }

    [Fact]
    public async Task A_cached_session_is_never_answered_for_another_user()
    {
        SessionLiveness liveness = New((userId, _, _, _) => Task.FromResult(userId == alice));

        Assert.True(await liveness.IsLiveAsync(alice, session, Ct));
        Assert.False(await liveness.IsLiveAsync(bob, session, Ct));
    }

    [Fact]
    public async Task With_no_cache_every_call_looks_up_and_a_failure_propagates()
    {
        int lookups = 0;
        SessionLiveness liveness = new(
            (_, _, _, _) =>
            {
                lookups++;
                return lookups < 3 ? Task.FromResult(true) : throw new InvalidOperationException("database down");
            },
            clock,
            new SessionLivenessOptions { CacheDuration = TimeSpan.Zero });

        await liveness.IsLiveAsync(alice, session, Ct);
        await liveness.IsLiveAsync(alice, session, Ct);
        await Assert.ThrowsAsync<InvalidOperationException>(() => liveness.IsLiveAsync(alice, session, Ct));
        Assert.Equal(3, lookups);
    }

    [Fact]
    public async Task The_cache_stays_bounded()
    {
        int lookups = 0;
        SessionLiveness liveness = new(
            (_, _, _, _) =>
            {
                lookups++;
                return Task.FromResult(true);
            },
            clock,
            new SessionLivenessOptions { MaxEntries = 2 });
        Guid first = Guid.NewGuid();

        await liveness.IsLiveAsync(alice, first, Ct);
        await liveness.IsLiveAsync(alice, Guid.NewGuid(), Ct);
        await liveness.IsLiveAsync(alice, Guid.NewGuid(), Ct);
        await liveness.IsLiveAsync(alice, first, Ct);

        Assert.Equal(4, lookups);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(31)]
    public void Cache_duration_outside_0_to_30_seconds_is_refused(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SessionLivenessOptions { CacheDuration = TimeSpan.FromSeconds(seconds) }.Validated());
    }

    private SessionLiveness New(Func<Guid, Guid, DateTime, CancellationToken, Task<bool>> lookup) =>
        new(lookup, clock, new SessionLivenessOptions { CacheDuration = TimeSpan.FromSeconds(5) });

    private sealed class FakeClock : IClock
    {
        public DateTime Now { get; set; } = new(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);

        public DateTime UtcNow => Now;
    }
}
