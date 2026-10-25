using System.Collections.Concurrent;
using Auth.DAL.Repositories;
using Auth.Services.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Services.Security;

/// <summary>Settings for the live-session check on access tokens (configuration section <c>SessionLiveness</c>).</summary>
public sealed class SessionLivenessOptions
{
    public const string SectionName = "SessionLiveness";

    /// <summary>How long a lookup result is reused. 0 to 30 seconds; 0 disables the cache.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Upper bound on cached sessions; when reached, the cache is emptied (simple and bounded).</summary>
    public int MaxEntries { get; set; } = 10_000;

    public SessionLivenessOptions Validated()
    {
        if (CacheDuration < TimeSpan.Zero || CacheDuration > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(CacheDuration), "SessionLiveness:CacheDuration must be 0 to 30 seconds.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(MaxEntries, 1, nameof(MaxEntries));
        return this;
    }
}

/// <summary>
/// Is the session behind an access token still live? A signed access token alone stays valid until it expires (15
/// min); this check makes logout, logout-all, revoking a session, a password change or reset, a role change (all revoke
/// the families) and deactivating the account take effect within <see cref="SessionLivenessOptions.CacheDuration"/>.
/// The cache is per instance: the <c>Invalidate</c> methods make a change immediate on the instance that made it; other
/// instances see it when their entry expires.
/// </summary>
public interface ISessionLiveness
{
    /// <summary>
    /// True when the family <paramref name="sessionId"/> of <paramref name="userId"/> still has a token that is neither
    /// revoked nor expired and the user is active. One indexed lookup, cached briefly per family; concurrent misses for
    /// the same session share one lookup.
    /// </summary>
    /// <exception cref="Exception">A lookup failure propagates: the caller must fail closed.</exception>
    Task<bool> IsLiveAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken);

    /// <summary>Forgets the cached result for one session (call after ending it).</summary>
    void Invalidate(Guid sessionId);

    /// <summary>Forgets the cached results for every session of one user (call after ending all of them).</summary>
    void InvalidateUser(Guid userId);

    /// <summary>Forgets every cached result (call after a change that ends the sessions of many users).</summary>
    void InvalidateAll();
}

internal sealed class SessionLiveness : ISessionLiveness
{
    private readonly Func<Guid, Guid, DateTime, CancellationToken, Task<bool>> lookup;
    private readonly IClock clock;
    private readonly SessionLivenessOptions options;
    private readonly ConcurrentDictionary<Guid, Entry> cache = new();
    private readonly ConcurrentDictionary<(Guid UserId, Guid SessionId), Lazy<Task<bool>>> pending = new();
    private readonly Lock evicting = new();

    /// <summary>Approximate number of cached entries (ConcurrentDictionary.Count takes every lock).</summary>
    private int count;

    /// <summary>Bumped by every invalidation: a lookup that started before one does not cache its (maybe stale) answer.</summary>
    private long generation;

    public SessionLiveness(IServiceScopeFactory scopes, IClock clock, SessionLivenessOptions options)
        : this(
            async (userId, sessionId, now, cancellationToken) =>
            {
                await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                return await scope.ServiceProvider.GetRequiredService<IRefreshTokenRepository>().IsSessionLiveAsync(sessionId, userId, now, cancellationToken);
            },
            clock,
            options)
    {
    }

    internal SessionLiveness(Func<Guid, Guid, DateTime, CancellationToken, Task<bool>> lookup, IClock clock, SessionLivenessOptions options)
    {
        this.lookup = lookup;
        this.clock = clock;
        this.options = options.Validated();
    }

    public async Task<bool> IsLiveAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken)
    {
        // Keyed by family, but the entry also remembers its user: a family id with another user never reuses it.
        if (cache.TryGetValue(sessionId, out Entry? cached) && cached.UserId == userId && cached.ValidUntil > clock.UtcNow)
        {
            return cached.Live;
        }

        // Concurrent misses for the same session share one lookup. It runs without the caller's token so one aborted
        // request cannot fail the others; each caller still stops waiting when its own request is aborted.
        (Guid, Guid) key = (userId, sessionId);
        Lazy<Task<bool>> shared = pending.GetOrAdd(key, k => new Lazy<Task<bool>>(() => LookupAsync(k)));
        return await shared.Value.WaitAsync(cancellationToken);
    }

    public void Invalidate(Guid sessionId)
    {
        Interlocked.Increment(ref generation);
        Remove(sessionId);
    }

    public void InvalidateUser(Guid userId)
    {
        Interlocked.Increment(ref generation);
        foreach (KeyValuePair<Guid, Entry> entry in cache)
        {
            if (entry.Value.UserId == userId)
            {
                Remove(entry.Key);
            }
        }
    }

    public void InvalidateAll()
    {
        Interlocked.Increment(ref generation);
        lock (evicting)
        {
            cache.Clear();
            Interlocked.Exchange(ref count, 0);
        }
    }

    private async Task<bool> LookupAsync((Guid UserId, Guid SessionId) key)
    {
        try
        {
            long startedIn = Interlocked.Read(ref generation);
            DateTime now = clock.UtcNow;
            bool live = await lookup(key.UserId, key.SessionId, now, CancellationToken.None);
            if (options.CacheDuration > TimeSpan.Zero && Interlocked.Read(ref generation) == startedIn)
            {
                Store(key.SessionId, new Entry(key.UserId, live, now + options.CacheDuration));
            }

            return live;
        }
        finally
        {
            pending.TryRemove(key, out _);
        }
    }

    private void Store(Guid sessionId, Entry entry)
    {
        if (Volatile.Read(ref count) >= options.MaxEntries)
        {
            Evict();
        }

        if (cache.TryAdd(sessionId, entry))
        {
            Interlocked.Increment(ref count);
        }
        else
        {
            cache[sessionId] = entry;
        }
    }

    /// <summary>Drops expired entries first; only when that is not enough is the whole cache emptied (bounded).</summary>
    private void Evict()
    {
        lock (evicting)
        {
            if (Volatile.Read(ref count) < options.MaxEntries)
            {
                return;
            }

            DateTime now = clock.UtcNow;
            foreach (KeyValuePair<Guid, Entry> entry in cache)
            {
                if (entry.Value.ValidUntil <= now)
                {
                    Remove(entry.Key);
                }
            }

            if (Volatile.Read(ref count) >= options.MaxEntries)
            {
                cache.Clear();
                Interlocked.Exchange(ref count, 0);
            }
        }
    }

    private void Remove(Guid sessionId)
    {
        if (cache.TryRemove(sessionId, out _))
        {
            Interlocked.Decrement(ref count);
        }
    }

    private sealed record Entry(Guid UserId, bool Live, DateTime ValidUntil);
}
