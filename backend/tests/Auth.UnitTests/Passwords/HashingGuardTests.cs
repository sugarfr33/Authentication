using Auth.Services.Passwords;
using Auth.Services.Security;

namespace Auth.UnitTests.Passwords;

/// <summary>T11: the timing guard does the same hashing work on every path; the bounded gate caps concurrent Argon2 calls.</summary>
public class HashingGuardTests
{
    private const string Password = "violet-canyon-7319";

    [Fact]
    public void Unknown_inactive_locked_and_wrong_password_paths_each_cost_exactly_one_Verify_and_look_the_same()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);
        string stored = hasher.Hash(Password);
        hasher.Reset();

        CredentialCheck unknown = Measure(() => guard.CheckPassword(Password, null, accountUsable: false), hasher, out int unknownCalls);
        CredentialCheck lockedWithRightPassword = Measure(() => guard.CheckPassword(Password, stored, accountUsable: false), hasher, out int lockedCalls);
        CredentialCheck wrongPassword = Measure(() => guard.CheckPassword("wrong-password-99", stored, accountUsable: true), hasher, out int wrongCalls);
        CredentialCheck valid = Measure(() => guard.CheckPassword(Password, stored, accountUsable: true), hasher, out int validCalls);

        Assert.Equal(CredentialCheck.Invalid, unknown);
        Assert.Equal(CredentialCheck.Invalid, lockedWithRightPassword);
        Assert.Equal(CredentialCheck.Invalid, wrongPassword);
        Assert.Equal(CredentialCheck.Valid, valid);
        Assert.Equal([1, 1, 1, 1], new[] { unknownCalls, lockedCalls, wrongCalls, validCalls });
        Assert.Equal(1, hasher.HashCalls);
    }

    [Fact]
    public void Dummy_hash_uses_the_current_parameters_so_the_work_matches_a_real_account()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);

        guard.CheckPassword(Password, null, accountUsable: false);

        Assert.StartsWith("$argon2id$v=19$m=1024,t=1,p=1$", hasher.LastVerifiedHash, StringComparison.Ordinal);
    }

    [Fact]
    public void Overlong_passwords_are_rejected_before_any_Verify_on_every_path()
    {
        CountingHasher hasher = new();
        AuthTimingGuard guard = new(hasher);
        string stored = hasher.Hash(Password);
        hasher.Reset();
        string tooLong = new('a', IPasswordPolicy.MaximumLength + 1);

        Assert.Equal(CredentialCheck.Invalid, guard.CheckPassword(tooLong, stored, accountUsable: true));
        Assert.Equal(CredentialCheck.Invalid, guard.CheckPassword(tooLong, null, accountUsable: false));
        Assert.Equal(0, hasher.VerifyCalls);
        Assert.Equal(CredentialCheck.Valid, guard.CheckPassword(Password, stored, accountUsable: true));
        Assert.Equal(1, hasher.VerifyCalls);
    }

    [Fact]
    public async Task At_most_N_hash_operations_run_at_once_and_excess_callers_get_busy()
    {
        using ManualResetEventSlim release = new(false);
        BlockingHasher inner = new(release);
        using BoundedPasswordHasher bounded = new(inner, new PasswordHashingLimits { MaxConcurrentOperations = 2, QueueTimeout = TimeSpan.FromMilliseconds(200) }.Validated());

        Task<PasswordVerifyResult>[] running = [Task.Run(() => bounded.Verify("a", "b")), Task.Run(() => bounded.Verify("a", "b"))];
        SpinWait.SpinUntil(() => inner.Active == 2, TimeSpan.FromSeconds(5));

        Assert.Throws<PasswordHashingBusyException>(() => bounded.Verify("a", "b"));
        Assert.Equal(2, inner.MaxObserved);

        release.Set();
        await Task.WhenAll(running);
        Assert.Equal(PasswordVerifyResult.Failed, bounded.Verify("a", "b"));
        Assert.Equal(2, inner.MaxObserved);
    }

    [Fact]
    public void Lock_durations_double_and_cap()
    {
        LockoutOptions options = new LockoutOptions().Validated();

        IEnumerable<TimeSpan> durations = Enumerable.Range(1, 9).Select(options.DurationFor);

        Assert.Equal(
            [1, 2, 4, 8, 16, 32, 60, 60, 60],
            durations.Select(d => (int)d.TotalMinutes));
    }

    private static CredentialCheck Measure(Func<CredentialCheck> check, CountingHasher hasher, out int verifyCalls)
    {
        int before = hasher.VerifyCalls;
        CredentialCheck result = check();
        verifyCalls = hasher.VerifyCalls - before;
        return result;
    }

    /// <summary>The real Argon2 hasher (fast test parameters), counting calls.</summary>
    private sealed class CountingHasher : IPasswordHasher
    {
        private readonly Argon2PasswordHasher inner = new(Argon2PasswordHasherTests.FastOptions);

        public int VerifyCalls { get; private set; }

        public int HashCalls { get; private set; }

        public string LastVerifiedHash { get; private set; } = string.Empty;

        public string Hash(string password)
        {
            HashCalls++;
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
