using System.Text.Json;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Services.ClientApplications;

/// <summary>
/// The cached read model of one ACTIVE client application: canonical client id (as stored), normalized origins and
/// exact redirect URIs. Origins that are not allowed (plain http outside Development) are left out. RequireRole (T30):
/// only holders of one of the application's roles may sign in to it.
/// </summary>
public sealed record ClientApplicationView(
    Guid Id, string ClientId, IReadOnlySet<string> Origins, IReadOnlyList<string> RedirectUris, IReadOnlyList<string> PostLogoutRedirectUris, bool RequireRole = false);

/// <summary>
/// Browser origins allowed to call the API with credentials (the AllowedOrigins entries of active client applications),
/// and the per-client read model the OAuth endpoints use (one client's own origins and redirect URIs).
/// </summary>
public interface IClientApplicationOriginProvider
{
    /// <summary>Normalized origins (<c>scheme://host[:port]</c>, lower case, no trailing slash).</summary>
    Task<IReadOnlySet<string>> GetAllowedOriginsAsync(CancellationToken cancellationToken);

    /// <summary>Exact (normalized) match against <see cref="GetAllowedOriginsAsync"/>. Wildcards are never allowed.</summary>
    Task<bool> IsAllowedAsync(string origin, CancellationToken cancellationToken);

    /// <summary>The active application with this client id (any letter case, as the database collation), or null.</summary>
    Task<ClientApplicationView?> FindActiveAsync(string? clientId, CancellationToken cancellationToken);

    /// <summary>
    /// The active application with this client id when <paramref name="origin"/> is one of ITS OWN registered origins
    /// (exact, normalized), or null: being registered for another application is not enough.
    /// </summary>
    Task<ClientApplicationView?> MatchOriginAsync(string? clientId, string? origin, CancellationToken cancellationToken);

    /// <summary>
    /// Drops the cached list: the next call reads the registry. The registry calls it after every change, so a change is
    /// immediate on this instance; other instances see it within <see cref="ClientApplicationOriginOptions.CacheDuration"/>.
    /// </summary>
    void Invalidate();
}

/// <summary>How long the origin allow-list is cached before the registry is read again.</summary>
public sealed class ClientApplicationOriginOptions
{
    public TimeSpan CacheDuration { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// When true (production), only https origins are accepted from the registry; plain http only for loopback hosts
    /// (localhost, 127.0.0.1, [::1]). The host sets false in Development.
    /// </summary>
    public bool RequireHttps { get; init; } = true;
}

/// <summary>Singleton with a short-TTL cache over the ClientApplication registry.</summary>
internal sealed class ClientApplicationOriginProvider(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    ClientApplicationOriginOptions options) : IClientApplicationOriginProvider, IDisposable
{
    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private Snapshot? snapshot;

    /// <summary>Bumped by <see cref="Invalidate"/>: a load that overlaps an invalidation is used once but not cached.</summary>
    private long generation;

    public async Task<IReadOnlySet<string>> GetAllowedOriginsAsync(CancellationToken cancellationToken) =>
        (await CurrentAsync(cancellationToken)).Origins;

    public async Task<ClientApplicationView?> FindActiveAsync(string? clientId, CancellationToken cancellationToken) =>
        string.IsNullOrWhiteSpace(clientId) || clientId.Length > 100
            ? null
            : (await CurrentAsync(cancellationToken)).Applications.GetValueOrDefault(clientId);

    public async Task<ClientApplicationView?> MatchOriginAsync(string? clientId, string? origin, CancellationToken cancellationToken) =>
        OriginNormalizer.TryNormalize(origin, out string normalized)
        && await FindActiveAsync(clientId, cancellationToken) is ClientApplicationView view
        && view.Origins.Contains(normalized)
            ? view
            : null;

    private async Task<Snapshot> CurrentAsync(CancellationToken cancellationToken)
    {
        Snapshot? current = snapshot;
        if (current is not null && clock.UtcNow < current.LoadedUtc + options.CacheDuration)
        {
            return current;
        }

        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            current = snapshot;
            if (current is not null && clock.UtcNow < current.LoadedUtc + options.CacheDuration)
            {
                return current;
            }

            long loadedIn = Interlocked.Read(ref generation);
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            IReadOnlyList<ClientApplication> active = await scope.ServiceProvider.GetRequiredService<IClientApplicationRepository>()
                .GetActiveAsync(cancellationToken);

            HashSet<string> origins = new(StringComparer.Ordinal);
            Dictionary<string, ClientApplicationView> applications = new(StringComparer.OrdinalIgnoreCase);
            foreach (ClientApplication application in active)
            {
                HashSet<string> own = new(StringComparer.Ordinal);
                foreach (string entry in ClientApplicationLists.Read(application.AllowedOrigins))
                {
                    if (OriginNormalizer.TryNormalize(entry, options.RequireHttps, out string normalized))
                    {
                        own.Add(normalized);
                    }
                }

                origins.UnionWith(own);
                applications[application.ClientId] = new ClientApplicationView(
                    application.Id, application.ClientId, own, ClientApplicationLists.Read(application.RedirectUris), ClientApplicationLists.Read(application.PostLogoutRedirectUris), application.RequireRole);
            }

            Snapshot loaded = new(clock.UtcNow, origins, applications);
            if (Interlocked.Read(ref generation) == loadedIn)
            {
                snapshot = loaded;
            }

            return loaded;
        }
        finally
        {
            refreshLock.Release();
        }
    }

    public void Dispose() => refreshLock.Dispose();

    public void Invalidate()
    {
        Interlocked.Increment(ref generation);
        snapshot = null;
    }

    public async Task<bool> IsAllowedAsync(string origin, CancellationToken cancellationToken) =>
        OriginNormalizer.TryNormalize(origin, out string normalized)
        && (await GetAllowedOriginsAsync(cancellationToken)).Contains(normalized);

    private sealed record Snapshot(DateTime LoadedUtc, IReadOnlySet<string> Origins, IReadOnlyDictionary<string, ClientApplicationView> Applications);
}

/// <summary>The JSON string arrays stored in ClientApplication (origins, redirect URIs): one reader for every caller.</summary>
internal static class ClientApplicationLists
{
    /// <summary>The entries, or none for a malformed value (which then grants nothing).</summary>
    public static string[] Read(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

/// <summary>Canonical origin form used for every comparison.</summary>
public static class OriginNormalizer
{
    /// <summary>
    /// Accepts only absolute http/https origins without path, query, fragment or user info, e.g. <c>https://app.example.com</c>.
    /// "*", "null" and anything else are rejected.
    /// </summary>
    public static bool TryNormalize(string? value, out string origin)
    {
        origin = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || !Uri.TryCreate(value.Trim(), UriKind.Absolute, out Uri? uri))
        {
            return false;
        }

        if ((uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || uri.UserInfo.Length > 0
            || uri.AbsolutePath != "/"
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || uri.Host.Contains('*', StringComparison.Ordinal))
        {
            return false;
        }

        origin = uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
        return true;
    }

    /// <summary>
    /// Like <see cref="TryNormalize(string?, out string)"/>, and when <paramref name="requireHttps"/> is true also rejects plain
    /// http unless the host is loopback (localhost, 127.0.0.1, [::1]).
    /// </summary>
    public static bool TryNormalize(string? value, bool requireHttps, out string origin)
    {
        if (!TryNormalize(value, out origin) || (requireHttps && !IsHttpsOrLoopback(origin)))
        {
            origin = string.Empty;
            return false;
        }

        return true;
    }

    /// <summary>True for https origins and for http on a loopback host.</summary>
    public static bool IsHttpsOrLoopback(string normalizedOrigin)
    {
        if (normalizedOrigin.StartsWith("https://", StringComparison.Ordinal))
        {
            return true;
        }

        return Uri.TryCreate(normalizedOrigin, UriKind.Absolute, out Uri? uri) && uri.IsLoopback;
    }

    /// <summary>The origin (<c>scheme://host[:port]</c>) of an absolute URL such as a Referer, or false.</summary>
    public static bool TryGetOrigin(string? url, out string origin)
    {
        origin = string.Empty;
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            return false;
        }

        origin = uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
        return true;
    }
}
