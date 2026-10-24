using Auth.Services.Passwords;
using Auth.Services.Security;

namespace Auth.UnitTests.Passwords;

/// <summary>T11: the timing guard does the same hashing work on every path; the bounded gate caps concurrent Argon2 calls.</summary>
public class HashingGuardTests
{
    private const string Password = "violet-canyon-7319";
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task Unknown_inactive_locked_and_wrong_password_paths_each_cost_exactly_one_Verify_and_look_the_same()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);
        string stored = hasher.Hash(Password);
        await guard.CheckPasswordAsync(Password, null, accountUsable: false, Ct);
        hasher.Reset();

        (CredentialCheck unknown, int unknownCalls) = await MeasureAsync(() => guard.CheckPasswordAsync(Password, null, accountUsable: false, Ct), hasher);
        (CredentialCheck locked, int lockedCalls) = await MeasureAsync(() => guard.CheckPasswordAsync(Password, stored, accountUsable: false, Ct), hasher);
        (CredentialCheck wrong, int wrongCalls) = await MeasureAsync(() => guard.CheckPasswordAsync("wrong-password-99", stored, accountUsable: true, Ct), hasher);
        (CredentialCheck valid, int validCalls) = await MeasureAsync(() => guard.CheckPasswordAsync(Password, stored, accountUsable: true, Ct), hasher);

        Assert.Equal(CredentialCheck.Invalid, unknown);
        Assert.Equal(CredentialCheck.Invalid, locked);
        Assert.Equal(CredentialCheck.Invalid, wrong);
        Assert.Equal(CredentialCheck.Valid, valid);
        Assert.Equal([1, 1, 1, 1], new[] { unknownCalls, lockedCalls, wrongCalls, validCalls });
        Assert.Equal(0, hasher.HashCalls);
    }

    [Fact]
    public async Task Dummy_hash_uses_the_current_parameters_and_is_made_once()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);

        await guard.CheckPasswordAsync(Password, null, accountUsable: false, Ct);
        await guard.CheckPasswordAsync(Password, null, accountUsable: false, Ct);

        Assert.StartsWith("$argon2id$v=19$m=1024,t=1,p=1$", hasher.LastVerifiedHash, StringComparison.Ordinal);
        Assert.Equal(1, hasher.HashCalls);
    }

    /// <summary>Review fix: a busy moment while making the dummy hash must not be cached as a permanent failure.</summary>
    [Fact]
    public async Task A_failure_while_making_the_dummy_hash_is_not_cached()
    {
        CountingHasher hasher = new() { FailNextHash = true };
        AuthTimingGuard guard = new(hasher);

        await Assert.ThrowsAsync<PasswordHashingBusyException>(() => guard.CheckPasswordAsync(Password, null, accountUsable: false, Ct));
        CredentialCheck retried = await guard.CheckPasswordAsync(Password, null, accountUsable: false, Ct);

        Assert.Equal(CredentialCheck.Invalid, retried);
        Assert.Equal(2, hasher.HashCalls);
        Assert.Equal(1, hasher.VerifyCalls);
    }

    [Fact]
    public async Task Overlong_passwords_are_rejected_before_any_Verify_on_every_path()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);
        string stored = hasher.Hash(Password);
        hasher.Reset();
        string tooLong = new('a', IPasswordPolicy.MaximumLength + 1);

        Assert.Equal(CredentialCheck.Invalid, await guard.CheckPasswordAsync(tooLong, stored, accountUsable: true, Ct));
        Assert.Equal(CredentialCheck.Invalid, await guard.CheckPasswordAsync(tooLong, null, accountUsable: false, Ct));
        Assert.Equal(0, hasher.VerifyCalls);
        Assert.Equal(0, hasher.HashCalls);
    }

    /// <summary>Audit MEDIUM-3: a huge raw password is refused before normalization (which copies it) and before Verify.</summary>
    [Fact]
    public async Task Raw_passwords_over_1024_chars_are_rejected_before_normalization_and_Verify()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);
        string stored = hasher.Hash(Password);
        hasher.Reset();

        Assert.Equal(CredentialCheck.Invalid, await guard.CheckPasswordAsync(new string('a', 1025), stored, accountUsable: true, Ct));
        Assert.Equal(CredentialCheck.Invalid, await guard.CheckPasswordAsync(new string('a', 5_000_000), null, accountUsable: false, Ct));
        Assert.Equal(0, hasher.VerifyCalls + hasher.HashCalls);
        Assert.Equal(1024, AuthTimingGuard.MaxRawPasswordLength);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    [InlineData(1000)]
    public void Hashing_concurrency_outside_1_to_64_is_refused(int concurrency)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordHashingLimits { MaxConcurrentOperations = concurrency }.Validated());
    }

    [Fact]
    public async Task At_most_N_hash_operations_run_at_once_and_excess_async_callers_get_busy()
    {
        using ManualResetEventSlim release = new(false);
        BlockingHasher inner = new(release);
        using BoundedPasswordHasher bounded = new(inner, new PasswordHashingLimits { MaxConcurrentOperations = 2, QueueTimeout = TimeSpan.FromMilliseconds(200) }.Validated());

        Task<PasswordVerifyResult>[] running = [bounded.VerifyAsync("a", "b", Ct), bounded.VerifyAsync("a", "b", Ct)];
        Assert.True(SpinWait.SpinUntil(() => inner.Active == 2, TimeSpan.FromSeconds(5)));

        await Assert.ThrowsAsync<PasswordHashingBusyException>(() => bounded.VerifyAsync("a", "b", Ct));
        Assert.Throws<PasswordHashingBusyException>(() => bounded.Verify("a", "b"));

        release.Set();
        await Task.WhenAll(running);
        Assert.Equal(PasswordVerifyResult.Failed, await bounded.VerifyAsync("a", "b", Ct));
        Assert.Equal(2, inner.MaxObserved);
    }

    [Fact]
    public async Task Waiting_for_a_slot_does_not_block_the_caller_thread()
    {
        using ManualResetEventSlim release = new(false);
        BlockingHasher inner = new(release);
        using BoundedPasswordHasher bounded = new(inner, new PasswordHashingLimits { MaxConcurrentOperations = 1, QueueTimeout = TimeSpan.FromSeconds(10) }.Validated());

        Task<PasswordVerifyResult> holder = bounded.VerifyAsync("a", "b", Ct);
        Assert.True(SpinWait.SpinUntil(() => inner.Active == 1, TimeSpan.FromSeconds(5)));

        Task<PasswordVerifyResult> queued = bounded.VerifyAsync("a", "b", Ct);

        Assert.False(queued.IsCompleted);
        release.Set();
        await Task.WhenAll(holder, queued);
    }

    [Fact]
    public void Lock_durations_double_and_cap()
    {
        LockoutOptions options = new LockoutOptions().Validated();

        IEnumerable<TimeSpan> durations = Enumerable.Range(1, 9).Select(options.DurationFor);

        Assert.Equal([1, 2, 4, 8, 16, 32, 60, 60, 60], durations.Select(d => (int)d.TotalMinutes));
    }

    private static async Task<(CredentialCheck Result, int VerifyCalls)> MeasureAsync(Func<Task<CredentialCheck>> check, CountingHasher hasher)
    {
        int before = hasher.VerifyCalls;
        CredentialCheck result = await check();
        return (result, hasher.VerifyCalls - before);
    }

    /// <summary>The real Argon2 hasher (fast test parameters), counting calls; the async methods use the defaults.</summary>
    private sealed class CountingHasher : IPasswordHasher
    {
        private readonly Argon2PasswordHasher inner = new(Argon2PasswordHasherTests.FastOptions);

        public bool FailNextHash { get; set; }

        public int VerifyCalls { get; private set; }

        public int HashCalls { get; private set; }

        public string LastVerifiedHash { get; private set; } = string.Empty;

        public string Hash(string password)
        {
            HashCalls++;
            if (FailNextHash)
            {
                FailNextHash = false;
                throw new PasswordHashingBusyException();
            }

            return inner.Hash(password);
        }

        public PasswordVerifyResult Verify(string password, string storedHash)
        {
            VerifyCalls++;
            LastVerifiedHash = storedHash;
            return inner.Verify(password, storedHash);
        }

        public void Reset() => (VerifyCalls, HashCalls) = (0, 0);
    }

    /// <summary>A hasher whose Verify blocks until released, recording the highest concurrency seen.</summary>
    private sealed class BlockingHasher(ManualResetEventSlim release) : IPasswordHasher
    {
        private int active;
        private int maxObserved;

        public int Active => Volatile.Read(ref active);

        public int MaxObserved => Volatile.Read(ref maxObserved);

        public string Hash(string password) => throw new NotSupportedException();

        public PasswordVerifyResult Verify(string password, string storedHash)
        {
            int now = Interlocked.Increment(ref active);
            int seen;
            while (now > (seen = Volatile.Read(ref maxObserved)) && Interlocked.CompareExchange(ref maxObserved, now, seen) != seen)
            {
            }

            release.Wait(TimeSpan.FromSeconds(10));
            Interlocked.Decrement(ref active);
            return PasswordVerifyResult.Failed;
        }
    }
}
