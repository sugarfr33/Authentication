using System.Text.Json;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Services.ClientApplications;

/// <summary>Browser origins allowed to call the API with credentials: the AllowedOrigin entries of active client applications.</summary>
public interface IClientApplicationOriginProvider
{
    /// <summary>Normalized origins (<c>scheme://host[:port]</c>, lower case, no trailing slash).</summary>
    Task<IReadOnlySet<string>> GetAllowedOriginsAsync(CancellationToken cancellationToken);

    /// <summary>Exact (normalized) match against <see cref="GetAllowedOriginsAsync"/>. Wildcards are never allowed.</summary>
    Task<bool> IsAllowedAsync(string origin, CancellationToken cancellationToken);
}

/// <summary>How long the origin allow-list is cached before the registry is read again.</summary>
public sealed class ClientApplicationOriginOptions
{
    public TimeSpan CacheDuration { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>Singleton with a short-TTL cache over the ClientApplication registry.</summary>
internal sealed class ClientApplicationOriginProvider(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    ClientApplicationOriginOptions options) : IClientApplicationOriginProvider, IDisposable
{
    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private Snapshot? snapshot;

    public async Task<IReadOnlySet<string>> GetAllowedOriginsAsync(CancellationToken cancellationToken)
    {
        Snapshot? current = snapshot;
        if (current is not null && clock.UtcNow < current.LoadedUtc + options.CacheDuration)
        {
            return current.Origins;
        }

        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            current = snapshot;
            if (current is not null && clock.UtcNow < current.LoadedUtc + options.CacheDuration)
            {
                return current.Origins;
            }

            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            IReadOnlyList<ClientApplication> active = await scope.ServiceProvider.GetRequiredService<IClientApplicationRepository>()
                .GetActiveAsync(cancellationToken);

            HashSet<string> origins = new(StringComparer.Ordinal);
            foreach (ClientApplication application in active)
            {
                foreach (string entry in ReadJsonArray(application.AllowedOrigin))
                {
                    if (OriginNormalizer.TryNormalize(entry, out string normalized))
                    {
                        origins.Add(normalized);
                    }
                }
            }

            snapshot = new Snapshot(clock.UtcNow, origins);
            return origins;
        }
        finally
        {
            refreshLock.Release();
        }
    }

    public void Dispose() => refreshLock.Dispose();

    public async Task<bool> IsAllowedAsync(string origin, CancellationToken cancellationToken) =>
        OriginNormalizer.TryNormalize(origin, out string normalized)
        && (await GetAllowedOriginsAsync(cancellationToken)).Contains(normalized);

    private static string[] ReadJsonArray(string json)
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

    private sealed record Snapshot(DateTime LoadedUtc, IReadOnlySet<string> Origins);
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
