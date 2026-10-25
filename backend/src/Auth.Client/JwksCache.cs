using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Client;

/// <summary>The usable signing keys of one JWKS, by kid. Each key is used only with its own algorithm.</summary>
internal sealed class JwksKeys(IReadOnlyDictionary<string, JsonWebKey> byKid)
{
    public int Count => byKid.Count;

    public bool Contains(string? kid) => kid is not null && byKid.ContainsKey(kid);

    /// <summary>The key with this kid whose own alg is exactly <paramref name="alg"/>; empty otherwise.</summary>
    public IEnumerable<SecurityKey> Resolve(string? kid, string? alg) =>
        kid is not null && byKid.TryGetValue(kid, out JsonWebKey? key) && string.Equals(key.Alg, alg, StringComparison.Ordinal) ? [key] : [];
}

/// <summary>No signing keys could be loaded (first use with central auth unreachable, or the last good set is too old).</summary>
internal sealed class JwksUnavailableException : Exception
{
    public JwksUnavailableException()
    {
    }

    public JwksUnavailableException(string message)
        : base(message)
    {
    }

    public JwksUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The JWKS cache of one scheme (docs/t22-client-extension.md section 5), with the scheme's options snapshot taken at
/// first use (a change needs a restart).
/// <list type="bullet">
/// <item>First use, an unknown kid, or keys older than JwksMaxStaleness: the caller waits for one fetch (single flight),
/// rate limited to one unplanned fetch per JwksMinRefreshInterval.</item>
/// <item>Keys older than JwksRefreshInterval but usable: served at once while ONE background refresh runs
/// (stale-while-revalidate), so callers never queue behind a slow fetch.</item>
/// <item>After a failed refresh the last good set is kept until JwksMaxStaleness (with a rate-limited warning), then
/// callers get <see cref="JwksUnavailableException"/> (fail closed).</item>
/// </list>
/// </summary>
internal sealed partial class JwksCache(CentralAuthOptions options, IHttpClientFactory httpClients, TimeProvider time, ILogger logger) : IDisposable
{
    public const int MaxDocumentBytes = 64 * 1024;
    public const int MaxKeys = 20;
    private const int MinRsaBits = 2048;

    private readonly SemaphoreSlim gate = new(1, 1);
    private Snapshot? current;
    private DateTimeOffset? lastAttempt;
    private DateTimeOffset? lastStaleWarning;
    private bool lastFetchFailed;
    private int backgroundRunning;

    /// <summary>The options this cache (and the handler using it) works with: the scheme's snapshot at first use.</summary>
    public CentralAuthOptions Options => options;

    /// <summary>The running background refresh, if any (tests await it).</summary>
    internal Task? BackgroundRefresh { get; private set; }

    /// <summary>The keys to validate a token with <paramref name="kid"/> (null: whatever is current).</summary>
    public async Task<JwksKeys> GetKeysAsync(string? kid, CancellationToken cancellationToken)
    {
        Snapshot? snapshot = Volatile.Read(ref current);
        DateTimeOffset now = time.GetUtcNow();
        if (snapshot is not null && (kid is null || snapshot.Keys.Contains(kid)) && now - snapshot.FetchedUtc < options.JwksMaxStaleness)
        {
            if (now - snapshot.FetchedUtc >= options.JwksRefreshInterval)
            {
                StartBackgroundRefresh(now);
                WarnIfStale(snapshot, now);
            }

            return snapshot.Keys;
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            snapshot = current;
            now = time.GetUtcNow();
            if (snapshot is not null && (kid is null || snapshot.Keys.Contains(kid)) && now - snapshot.FetchedUtc < options.JwksRefreshInterval)
            {
                // Another caller refreshed while this one waited.
                return snapshot.Keys;
            }

            // Unplanned fetches (an unknown kid, or a retry after a failure) are rate limited for the whole cache.
            if (lastAttempt is DateTimeOffset last && now - last < options.JwksMinRefreshInterval)
            {
                return Fallback(snapshot, now, null);
            }

            return await FetchUnderGateAsync(snapshot, now).ConfigureAwait(false) ?? Fallback(snapshot, now, null);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose() => gate.Dispose();

    /// <summary>Keeps only well-formed signing keys of the two algorithms central auth signs with. Throws when none is usable.</summary>
    internal static JwksKeys Parse(string json)
    {
        JsonWebKeySet set = new(json);
        if (set.Keys.Count > MaxKeys)
        {
            throw new InvalidDataException("The JWKS has more than " + MaxKeys + " keys.");
        }

        Dictionary<string, JsonWebKey> byKid = new(StringComparer.Ordinal);
        foreach (JsonWebKey key in set.Keys)
        {
            if (!string.IsNullOrEmpty(key.Kid) && IsUsable(key))
            {
                byKid.TryAdd(key.Kid, key);
            }
        }

        return byKid.Count > 0 ? new JwksKeys(byKid) : throw new InvalidDataException("The JWKS has no usable signing key.");
    }

    private static bool IsUsable(JsonWebKey key)
    {
        if (key.Use is { Length: > 0 } use && use != JsonWebKeyUseNames.Sig)
        {
            return false;
        }

        return key.Alg switch
        {
            SecurityAlgorithms.EcdsaSha256 => key.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve && key.Crv == JsonWebKeyECTypes.P256
                && !string.IsNullOrEmpty(key.X) && !string.IsNullOrEmpty(key.Y) && string.IsNullOrEmpty(key.D),
            SecurityAlgorithms.RsaSha256 => key.Kty == JsonWebAlgorithmsKeyTypes.RSA && !string.IsNullOrEmpty(key.N) && !string.IsNullOrEmpty(key.E)
                && string.IsNullOrEmpty(key.D) && Base64UrlEncoder.DecodeBytes(key.N).Length * 8 >= MinRsaBits,
            _ => false,
        };
    }

    /// <summary>One fetch (the gate is held): the new keys, or null after a failure (logged).</summary>
    private async Task<JwksKeys?> FetchUnderGateAsync(Snapshot? snapshot, DateTimeOffset now)
    {
        lastAttempt = now;
        try
        {
            JwksKeys keys = await FetchAsync().ConfigureAwait(false);
            Volatile.Write(ref current, new Snapshot(keys, time.GetUtcNow()));
            lastFetchFailed = false;
            LogRefreshed(logger, keys.Count);
            return keys;
        }
#pragma warning disable CA1031 // Any fetch failure (network, redirect, timeout, bad document, odd URI) is a failed fetch: 401, never 500.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            lastFetchFailed = true;
            LogFetchFailed(logger, ex.GetType().Name);
            if (snapshot is not null)
            {
                WarnIfStale(snapshot, now);
            }

            return null;
        }
    }

    /// <summary>Starts one background refresh unless one runs or the last attempt is too recent.</summary>
    private void StartBackgroundRefresh(DateTimeOffset now)
    {
        if ((lastAttempt is DateTimeOffset last && now - last < options.JwksMinRefreshInterval) || Interlocked.CompareExchange(ref backgroundRunning, 1, 0) != 0)
        {
            return;
        }

        BackgroundRefresh = Task.Run(async () =>
        {
            try
            {
                await gate.WaitAsync().ConfigureAwait(false);
                try
                {
                    DateTimeOffset at = time.GetUtcNow();
                    Snapshot? snapshot = current;
                    bool due = snapshot is null || at - snapshot.FetchedUtc >= options.JwksRefreshInterval;
                    if (due && !(lastAttempt is DateTimeOffset previous && at - previous < options.JwksMinRefreshInterval))
                    {
                        await FetchUnderGateAsync(snapshot, at).ConfigureAwait(false);
                    }
                }
                finally
                {
                    gate.Release();
                }
            }
            finally
            {
                Volatile.Write(ref backgroundRunning, 0);
            }
        });
    }

    /// <summary>A Warning when keys are served after a failed refresh, at most once per JwksMinRefreshInterval.</summary>
    private void WarnIfStale(Snapshot snapshot, DateTimeOffset now)
    {
        if (!lastFetchFailed || (lastStaleWarning is DateTimeOffset last && now - last < options.JwksMinRefreshInterval))
        {
            return;
        }

        lastStaleWarning = now;
        LogStaleKeys(logger, (int)(now - snapshot.FetchedUtc).TotalMinutes);
    }

    /// <summary>No fetch now (or it failed): the last good set while it is not too old (for an unknown kid, validation then fails), else fail closed.</summary>
    private JwksKeys Fallback(Snapshot? snapshot, DateTimeOffset now, Exception? cause)
    {
        if (snapshot is not null && now - snapshot.FetchedUtc < options.JwksMaxStaleness)
        {
            return snapshot.Keys;
        }

        const string Message = "No central-auth signing keys are available.";
        throw cause is null ? new JwksUnavailableException(Message) : new JwksUnavailableException(Message, cause);
    }

    /// <summary>
    /// One fetch with its own timeout (not the request's token, so one aborted request does not spoil the shared fetch).
    /// Redirects are never followed (the primary handler has them off), so any 3xx fails here.
    /// </summary>
    private async Task<JwksKeys> FetchAsync()
    {
        using CancellationTokenSource timeout = new(options.JwksFetchTimeout);
        HttpClient client = httpClients.CreateClient(CentralAuthDefaults.JwksHttpClientName);
        using HttpRequestMessage request = new(HttpMethod.Get, options.JwksUri);
        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaxDocumentBytes)
        {
            throw new InvalidDataException("The JWKS response is too large.");
        }

        Stream body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        await using (body.ConfigureAwait(false))
        {
            byte[] buffer = new byte[MaxDocumentBytes + 1];
            int length = 0;
            int read;
            while ((read = await body.ReadAsync(buffer.AsMemory(length), timeout.Token).ConfigureAwait(false)) > 0)
            {
                length += read;
                if (length > MaxDocumentBytes)
                {
                    throw new InvalidDataException("The JWKS response is too large.");
                }
            }

            return Parse(Encoding.UTF8.GetString(buffer, 0, length));
        }
    }

    [LoggerMessage(EventId = 7201, Level = LogLevel.Information, Message = "Central-auth JWKS loaded ({KeyCount} usable keys)")]
    private static partial void LogRefreshed(ILogger logger, int keyCount);

    [LoggerMessage(EventId = 7202, Level = LogLevel.Warning, Message = "Central-auth JWKS fetch failed ({ExceptionType})")]
    private static partial void LogFetchFailed(ILogger logger, string exceptionType);

    [LoggerMessage(EventId = 7203, Level = LogLevel.Warning, Message = "Serving stale central-auth signing keys ({AgeMinutes} min old) because the JWKS cannot be refreshed; they are refused after JwksMaxStaleness")]
    private static partial void LogStaleKeys(ILogger logger, int ageMinutes);

    private sealed record Snapshot(JwksKeys Keys, DateTimeOffset FetchedUtc);
}

/// <summary>One <see cref="JwksCache"/> per authentication scheme, created with that scheme's options snapshot on first use.</summary>
internal sealed class JwksCacheRegistry(IHttpClientFactory httpClients, TimeProvider time, ILoggerFactory loggers) : IDisposable
{
    private readonly ConcurrentDictionary<string, Lazy<JwksCache>> caches = new(StringComparer.Ordinal);

    public JwksCache For(string scheme, CentralAuthOptions options) =>
        caches.GetOrAdd(scheme, _ => new Lazy<JwksCache>(() => new JwksCache(options, httpClients, time, loggers.CreateLogger<JwksCache>()))).Value;

    public void Dispose()
    {
        foreach (Lazy<JwksCache> cache in caches.Values.Where(c => c.IsValueCreated))
        {
            cache.Value.Dispose();
        }
    }
}
