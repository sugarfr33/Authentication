using System.Threading.RateLimiting;

namespace Auth.Api.RateLimiting;

/// <summary>
/// The per-client limit of /oauth/token (the "account" rule of the OAuthToken kind). It is applied by the endpoint
/// itself, only AFTER the request's Origin matched the client's own registered origin, and keyed on the canonical client
/// id: a request that merely names a client (any letter case) from elsewhere is counted per IP only, so nobody can
/// exhaust another application's bucket (T19 review and audit M1).
/// </summary>
internal static class ClientRateLimit
{
    /// <summary>One bucket per client, whatever the letter case of the client id presented.</summary>
    public static string Key(string canonicalClientId) => "client:" + canonicalClientId.ToLowerInvariant();

    /// <summary>True when the request may proceed; otherwise the 429 answer has been written.</summary>
    public static async Task<bool> TryAcquireAsync(HttpContext http, AccountRateLimiter limiter, string canonicalClientId)
    {
        http.Items[AccountKeyMiddleware.ItemKey] = Key(canonicalClientId);
        using RateLimitLease lease = await limiter.Limiter.AcquireAsync(http, 1, http.RequestAborted);
        if (lease.IsAcquired)
        {
            return true;
        }

        await AuthRateLimiting.WriteTooManyRequestsAsync(http, lease);
        return false;
    }
}
