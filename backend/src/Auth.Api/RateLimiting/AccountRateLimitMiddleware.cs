using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace Auth.Api.RateLimiting;

/// <summary>The per-account limiter, as a singleton (built once from the options).</summary>
internal sealed class AccountRateLimiter(IOptions<AuthRateLimitOptions> options) : IDisposable
{
    public PartitionedRateLimiter<HttpContext> Limiter { get; } = AuthRateLimiting.PerAccount(options.Value);

    public void Dispose() => Limiter.Dispose();
}

/// <summary>
/// Applies the per-account limit after AccountKeyMiddleware has found the account key. Requests without a key, and
/// paths without a per-account rule, pass through (they were already counted per IP).
/// </summary>
internal sealed class AccountRateLimitMiddleware(RequestDelegate next, AccountRateLimiter accountLimiter)
{
    public async Task InvokeAsync(HttpContext context)
    {
        using RateLimitLease lease = await accountLimiter.Limiter.AcquireAsync(context, 1, context.RequestAborted);
        if (!lease.IsAcquired)
        {
            await AuthRateLimiting.WriteTooManyRequestsAsync(context, lease);
            return;
        }

        await next(context);
    }
}
