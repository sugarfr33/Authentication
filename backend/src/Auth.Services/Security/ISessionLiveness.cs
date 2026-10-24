using System.Collections.Concurrent;
using Auth.DAL.Repositories;
using Auth.Services.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Services.Security;

/// <summary>Settings for the live-session check on access tokens (configuration section <c>SessionLiveness</c>).</summary>
public sealed class SessionLivenessOptions
{
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
/// min); this check makes logout, logout-all, revoking a session, a password change or reset (all revoke the families)
/// and deactivating the account take effect within <see cref="SessionLivenessOptions.CacheDuration"/>.
/// </summary>
public interface ISessionLiveness
{
    /// <summary>
    /// True when the family <paramref name="sessionId"/> of <paramref name="userId"/> still has a token that is neither
    /// revoked nor expired and the user is active. One indexed lookup, cached briefly per family.
    /// </summary>
    /// <exception cref="Exception">A lookup failure propagates: the caller must fail closed.</exception>
    Task<bool> IsLiveAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken);
}

internal sealed class SessionLiveness : ISessionLiveness
{
    private readonly Func<Guid, Guid, DateTime, CancellationToken, Task<bool>> lookup;
    private readonly IClock clock;
    private readonly SessionLivenessOptions options;
    private readonly ConcurrentDictionary<Guid, Entry> cache = new();

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
        DateTime now = clock.UtcNow;

        // Keyed by family, but the entry also remembers its user: a family id with another user never reuses it.
        if (cache.TryGetValue(sessionId, out Entry? cached) && cached.UserId == userId && cached.ValidUntil > now)
        {
            return cached.Live;
        }

        bool live = await lookup(userId, sessionId, now, cancellationToken);
        if (options.CacheDuration > TimeSpan.Zero)
        {
            if (cache.Count >= options.MaxEntries)
            {
                cache.Clear();
            }

            cache[sessionId] = new Entry(userId, live, now + options.CacheDuration);
        }

        return live;
    }

    private sealed record Entry(Guid UserId, bool Live, DateTime ValidUntil);
}
