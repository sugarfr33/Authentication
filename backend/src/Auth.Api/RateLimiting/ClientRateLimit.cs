using System.Threading.RateLimiting;

namespace Auth.Api.RateLimiting;

/// <summary>
/// The per-client limit of /oauth/token (the "account" rule of the OAuthToken kind), keyed on the client AND the caller's
/// IP: applied by the endpoint only after the request's Origin matched the client's own registered origin, with the
/// canonical client id in lower case. There is deliberately no bucket shared by all callers of one application: Origin is
/// only a header outside browsers and an application's origin is public, so a shared bucket could be drained from many
/// IPs to 429 every real user (T19 recheck M-A). Each address is limited per application and, by the per-IP rule,
/// overall; a script with many addresses spends only its own buckets.
/// </summary>
internal static class ClientRateLimit
{
    /// <summary>One bucket per client and caller IP (IPv6 per /64), whatever the letter case of the client id presented.</summary>
    public static string Key(string canonicalClientId, System.Net.IPAddress? caller) =>
        "client:" + canonicalClientId.ToLowerInvariant() + "|" + AuthRateLimiting.ClientPartitionKey(caller);

    /// <summary>True when the request may proceed; otherwise the 429 answer has been written.</summary>
    public static async Task<bool> TryAcquireAsync(HttpContext http, AccountRateLimiter limiter, string canonicalClientId)
    {
        http.Items[AccountKeyMiddleware.ItemKey] = Key(canonicalClientId, http.Connection.RemoteIpAddress);
        using RateLimitLease lease = await limiter.Limiter.AcquireAsync(http, 1, http.RequestAborted);
        if (lease.IsAcquired)
        {
            return true;
        }

        await AuthRateLimiting.WriteTooManyRequestsAsync(http, lease);
        return false;
    }
}
