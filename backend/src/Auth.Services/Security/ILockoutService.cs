using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;

namespace Auth.Services.Security;

/// <summary>Account lockout thresholds: exponential backoff per account.</summary>
public sealed class LockoutOptions
{
    /// <summary>Consecutive failures that trigger a lock.</summary>
    public int FailuresBeforeLockout { get; init; } = 5;

    /// <summary>The first lock; each further lock doubles it (1, 2, 4, 8 ... minutes).</summary>
    public TimeSpan BaseLockout { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Upper bound of a single lock.</summary>
    public TimeSpan MaxLockout { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Failures count toward a lock only while they keep coming: when the last failure is older than this, the counter
    /// starts again from zero (default 15 minutes).
    /// </summary>
    public TimeSpan FailureWindow { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The backoff level is forgotten after this long without a new lock, counted from the end of the last lock
    /// (default 24 hours): an account locked once months ago starts again at the first step.
    /// </summary>
    public TimeSpan LevelDecayAfter { get; init; } = TimeSpan.FromHours(24);

    internal LockoutOptions Validated()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(FailuresBeforeLockout, 1, nameof(FailuresBeforeLockout));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(BaseLockout, TimeSpan.Zero, nameof(BaseLockout));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxLockout, BaseLockout, nameof(MaxLockout));
        ArgumentOutOfRangeException.ThrowIfLessThan(FailureWindow, TimeSpan.FromMinutes(1), nameof(FailureWindow));
        ArgumentOutOfRangeException.ThrowIfLessThan(LevelDecayAfter, MaxLockout, nameof(LevelDecayAfter));
        return this;
    }

    /// <summary>Lock duration for the given level (1-based): Base * 2^(level-1), capped at Max.</summary>
    public TimeSpan DurationFor(int level)
    {
        int doublings = Math.Clamp(level - 1, 0, 30);
        double ticks = BaseLockout.Ticks * Math.Pow(2, doublings);
        return ticks >= MaxLockout.Ticks ? MaxLockout : TimeSpan.FromTicks((long)ticks);
    }
}

/// <summary>Raised when an account becomes locked; T17 writes it to the audit log as Lockout.</summary>
public sealed record AccountLockedOut(Guid UserId, DateTime LockoutEndUtc, int Level);

/// <summary>State after recording a failure.</summary>
/// <param name="IsLockedOut">True when the account is locked now (just locked, or already locked).</param>
/// <param name="LockedOut">Set only when THIS failure caused the lock (the audit hook).</param>
public sealed record LockoutResult(bool IsLockedOut, DateTime? LockoutEndUtc, int FailedCount, AccountLockedOut? LockedOut);

/// <summary>
/// Per-account lockout persisted on the User row (FailedLoginCount, LockoutEndUtc, LockoutLevel). Writes use the
/// User RowVersion with a bounded retry, so concurrent failures are never lost. Login (T13) must treat a locked
/// account exactly like a wrong password in the response. No extra columns: every counted failure sets UpdatedUtc,
/// which is then the time of the last failure for the <see cref="LockoutOptions.FailureWindow"/>; the level decay is
/// measured from LockoutEndUtc (kept after the lock expires).
/// </summary>
public interface ILockoutService
{
    Task<bool> IsLockedOutAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// Counts a failed sign-in. At <see cref="LockoutOptions.FailuresBeforeLockout"/> failures the account locks for
    /// the next backoff step and the counter restarts. Failures while locked are not counted.
    /// </summary>
    Task<LockoutResult> RegisterFailureAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>After a successful sign-in: clears the counter, the lock and the backoff level.</summary>
    Task ResetAsync(Guid userId, CancellationToken cancellationToken);
}

internal sealed class LockoutService(IUserRepository users, IUnitOfWork unitOfWork, IClock clock, LockoutOptions options) : ILockoutService
{
    private const int MaxAttempts = 5;

    public async Task<bool> IsLockedOutAsync(Guid userId, CancellationToken cancellationToken)
    {
        User? user = await users.GetByIdAsync(userId, cancellationToken);
        return user is not null && IsLocked(user, clock.UtcNow);
    }

    public Task<LockoutResult> RegisterFailureAsync(Guid userId, CancellationToken cancellationToken) =>
        WithRetryAsync(
            userId,
            user =>
            {
                DateTime now = clock.UtcNow;
                if (IsLocked(user, now))
                {
                    return (false, new LockoutResult(true, user.LockoutEndUtc, user.FailedLoginCount, null));
                }

                // A quiet period forgets old failures, and a long one the backoff level (T11 audit LOW-4).
                if (user.FailedLoginCount > 0 && now - user.UpdatedUtc >= options.FailureWindow)
                {
                    user.FailedLoginCount = 0;
                }

                if (user.LockoutLevel > 0 && user.LockoutEndUtc is DateTime lastLockEnd && now - lastLockEnd >= options.LevelDecayAfter)
                {
                    user.LockoutLevel = 0;
                }

                user.FailedLoginCount++;
                user.UpdatedUtc = now;
                if (user.FailedLoginCount < options.FailuresBeforeLockout)
                {
                    return (true, new LockoutResult(false, null, user.FailedLoginCount, null));
                }

                user.LockoutLevel++;
                user.LockoutEndUtc = now + options.DurationFor(user.LockoutLevel);
                user.FailedLoginCount = 0;
                return (true, new LockoutResult(
                    true,
                    user.LockoutEndUtc,
                    options.FailuresBeforeLockout,
                    new AccountLockedOut(user.Id, user.LockoutEndUtc.Value, user.LockoutLevel)));
            },
            missing: new LockoutResult(false, null, 0, null),
            cancellationToken);

    public Task ResetAsync(Guid userId, CancellationToken cancellationToken) =>
        WithRetryAsync(
            userId,
            user =>
            {
                bool changed = user.FailedLoginCount != 0 || user.LockoutLevel != 0 || user.LockoutEndUtc is not null;
                user.FailedLoginCount = 0;
                user.LockoutLevel = 0;
                user.LockoutEndUtc = null;
                return (changed, true);
            },
            missing: false,
            cancellationToken);

    private static bool IsLocked(User user, DateTime now) => user.LockoutEndUtc is not null && user.LockoutEndUtc > now;

    /// <summary>Read, change, save with the RowVersion check; on a concurrent write, reload and apply again.</summary>
    private async Task<T> WithRetryAsync<T>(Guid userId, Func<User, (bool Save, T Result)> change, T missing, CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            User? user = await users.GetByIdAsync(userId, cancellationToken);
            if (user is null)
            {
                return missing;
            }

            (bool save, T result) = change(user);
            if (!save)
            {
                return result;
            }

            try
            {
                await unitOfWork.SaveChangesAsync(cancellationToken);
                return result;
            }
            catch (ConcurrencyConflictException) when (attempt < MaxAttempts)
            {
                unitOfWork.ClearChanges();
            }
        }
    }
}
