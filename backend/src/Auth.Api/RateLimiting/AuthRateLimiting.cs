using System.Globalization;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Rate limiting for the auth endpoints with the framework limiter (no package). One global, chained limiter: a per-IP
/// fixed window, then a per-account fixed window when an account key was found. Requests to other paths are not
/// limited. Rejections are 429 ProblemDetails with Retry-After.
/// </summary>
internal static class AuthRateLimiting
{
    private const string NoLimit = "none";

    public static IServiceCollection AddAuthRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AuthRateLimitOptions>()
            .Bind(configuration.GetSection(AuthRateLimitOptions.SectionName))
            .Validate(options => options.IsValid(), "RateLimiting is invalid: every rule needs PermitLimit > 0 and Window > 0; MaxAccountBodyBytes must be 1..1048576.")
            .ValidateOnStart();

        services.AddSingleton<AccountRateLimiter>();
        services.AddRateLimiter(_ => { });
        services.AddOptions<RateLimiterOptions>().Configure<IOptions<AuthRateLimitOptions>>((limiter, auth) =>
        {
            AuthRateLimitOptions settings = auth.Value;
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            // Per IP only here, so it counts the request BEFORE the body is read; the per-account limit runs after the
            // account key is known (AccountRateLimitMiddleware).
            limiter.GlobalLimiter = PerIp(settings);
            limiter.OnRejected = WriteRejectionAsync;
        });

        return services;
    }

    /// <summary>
    /// Trusts X-Forwarded-For/Proto only from the configured ForwardedHeaders:KnownProxies. Without that setting the
    /// headers are ignored entirely, so a client cannot spoof its IP (and its rate-limit partition).
    /// </summary>
    public static bool ConfigureForwardedHeaders(this IServiceCollection services, IConfiguration configuration)
    {
        string[] proxies = configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
        if (proxies.Length == 0)
        {
            return false;
        }

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();
            foreach (string proxy in proxies)
            {
                options.KnownProxies.Add(IPAddress.Parse(proxy));
            }
        });
        return true;
    }

    private static PartitionedRateLimiter<HttpContext> PerIp(AuthRateLimitOptions settings) =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            if (!TryGetPolicy(settings, context, out AuthRateLimitKind kind, out AuthRateLimitPolicy? policy))
            {
                return RateLimitPartition.GetNoLimiter(NoLimit);
            }

            return FixedWindow(kind + "|ip|" + ClientPartitionKey(context.Connection.RemoteIpAddress), policy.PerIp);
        });

    /// <summary>
    /// IPv4 clients are partitioned per address. IPv6 clients are partitioned per /64, because one subscriber usually
    /// holds a whole /64 and could otherwise rotate addresses to escape the limit. IPv4-mapped IPv6 counts as IPv4.
    /// </summary>
    internal static string ClientPartitionKey(IPAddress? address)
    {
        if (address is null)
        {
            return "unknown";
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        byte[] bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes) + "/64";
    }

    internal static PartitionedRateLimiter<HttpContext> PerAccount(AuthRateLimitOptions settings) =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            if (!TryGetPolicy(settings, context, out AuthRateLimitKind kind, out AuthRateLimitPolicy? policy)
                || policy.PerAccount is null
                || context.Items[AccountKeyMiddleware.ItemKey] is not string account)
            {
                return RateLimitPartition.GetNoLimiter(NoLimit);
            }

            return FixedWindow(kind + "|account|" + account, policy.PerAccount);
        });

    private static bool TryGetPolicy(AuthRateLimitOptions settings, HttpContext context, out AuthRateLimitKind kind, out AuthRateLimitPolicy policy)
    {
        kind = default;
        policy = null!;
        if (HttpMethods.IsOptions(context.Request.Method) || settings.Resolve(context.Request.Path) is not AuthRateLimitKind resolved)
        {
            return false;
        }

        kind = resolved;
        return settings.Policies.TryGetValue(kind, out policy!);
    }

    private static RateLimitPartition<string> FixedWindow(string key, RateLimitRule rule) =>
        RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = rule.PermitLimit,
            Window = rule.Window,
            QueueLimit = 0,
            AutoReplenishment = true,
        });

    private static ValueTask WriteRejectionAsync(OnRejectedContext context, CancellationToken cancellationToken) =>
        new(WriteTooManyRequestsAsync(context.HttpContext, context.Lease));

    /// <summary>429 ProblemDetails with Retry-After from the lease (seconds until the window resets).</summary>
    internal static async Task WriteTooManyRequestsAsync(HttpContext http, RateLimitLease lease)
    {
        TimeSpan retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan wait) ? wait : TimeSpan.FromSeconds(60);
        http.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        http.Response.Headers[HeaderNames.RetryAfter] = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);

        IProblemDetailsService problems = http.RequestServices.GetRequiredService<IProblemDetailsService>();
        await problems.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = http,
            ProblemDetails = new ProblemDetails { Status = StatusCodes.Status429TooManyRequests, Title = "Too many requests." },
        });
    }
}
