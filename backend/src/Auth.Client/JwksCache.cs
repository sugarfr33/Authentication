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
/// The JWKS cache of one scheme (docs/t22-client-extension.md section 5). Filled on first use, refreshed when older than
/// JwksRefreshInterval, and refreshed for an unknown kid at most once per JwksMinRefreshInterval (one fetch at a time;
/// concurrent callers share it). Never a fetch per request. If a refresh fails, the last good set is kept until
/// JwksMaxStaleness; with no usable set at all, callers get <see cref="JwksUnavailableException"/> (fail closed).
/// </summary>
internal sealed partial class JwksCache(CentralAuthOptions options, IHttpClientFactory httpClients, TimeProvider time, ILogger logger) : IDisposable
{
    public const int MaxDocumentBytes = 64 * 1024;
    public const int MaxKeys = 20;
    private const int MinRsaBits = 2048;

    private readonly SemaphoreSlim gate = new(1, 1);
    private Snapshot? current;
    private DateTimeOffset? lastAttempt;

    /// <summary>The keys to validate a token with <paramref name="kid"/> (null: whatever is current).</summary>
    public async Task<JwksKeys> GetKeysAsync(string? kid, CancellationToken cancellationToken)
    {
        if (Usable(Volatile.Read(ref current), kid, time.GetUtcNow()) is JwksKeys ready)
        {
            return ready;
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Snapshot? snapshot = current;
            DateTimeOffset now = time.GetUtcNow();
            if (Usable(snapshot, kid, now) is JwksKeys refreshed)
            {
                // Another caller refreshed while this one waited.
                return refreshed;
            }

            // Unplanned fetches (an unknown kid, or a retry after a failure) are rate limited for the whole cache.
            if (lastAttempt is DateTimeOffset last && now - last < options.JwksMinRefreshInterval)
            {
                return Fallback(snapshot, now, null);
            }

            lastAttempt = now;
            try
            {
                JwksKeys keys = await FetchAsync().ConfigureAwait(false);
                Volatile.Write(ref current, new Snapshot(keys, now));
                LogRefreshed(logger, keys.Count);
                return keys;
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or InvalidDataException or ArgumentException or FormatException)
            {
                LogFetchFailed(logger, ex.GetType().Name);
                return Fallback(snapshot, now, ex);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose() => gate.Dispose();

    /// <summary>Keeps only well-formed signing keys of the two algorithms central auth uses. Throws when none is usable.</summary>
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

    private JwksKeys? Usable(Snapshot? snapshot, string? kid, DateTimeOffset now) =>
        snapshot is not null && now - snapshot.FetchedUtc < options.JwksRefreshInterval && (kid is null || snapshot.Keys.Contains(kid))
            ? snapshot.Keys
            : null;

    /// <summary>
    /// No fetch now: the last good set while it is not too old (for an unknown kid, validation then fails), else fail
    /// closed.
    /// </summary>
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

    [LoggerMessage(EventId = 7202, Level = LogLevel.Warning, Message = "Central-auth JWKS fetch failed ({ExceptionType}); keeping the last good keys while they are not too old")]
    private static partial void LogFetchFailed(ILogger logger, string exceptionType);

    private sealed record Snapshot(JwksKeys Keys, DateTimeOffset FetchedUtc);
}

/// <summary>One <see cref="JwksCache"/> per authentication scheme, created with that scheme's options on first use.</summary>
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
