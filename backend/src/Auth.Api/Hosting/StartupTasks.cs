using System.Net;
using System.Net.Sockets;
using Auth.Services.Passwords;
using Auth.Services.Security;

namespace Auth.Api.Hosting;

/// <summary>
/// Creates the timing guard's dummy hash at startup, outside any request, so the first unknown-account sign-in does
/// not pay for an extra Hash (audit LOW-5). A busy or cancelled start is harmless: the guard creates it on first need.
/// </summary>
internal sealed partial class TimingGuardWarmUp(IAuthTimingGuard guard, ILogger<TimingGuardWarmUp> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await guard.WarmUpAsync(stoppingToken);
        }
        catch (Exception ex) when (ex is PasswordHashingBusyException or OperationCanceledException)
        {
            LogWarmUpSkipped(logger);
        }
    }

    [LoggerMessage(EventId = 5100, Level = LogLevel.Information, Message = "Timing-guard warm-up skipped; the dummy hash will be created on first use")]
    private static partial void LogWarmUpSkipped(ILogger logger);
}

/// <summary>
/// Audit LOW-3: when no ForwardedHeaders:KnownProxies are configured, X-Forwarded-For is ignored and the per-IP limit
/// keys on the TCP peer. If that peer is loopback or private and sends X-Forwarded-For, the API is probably behind a
/// proxy that is not configured, and every user would share one IP bucket. This logs one warning per app instance
/// (outside Development), unless ForwardedHeaders:Direct=true says the deployment really has no proxy.
/// </summary>
internal sealed partial class ProxyMisconfigurationDetector(RequestDelegate next, ILogger<ProxyMisconfigurationDetector> logger)
{
    private int warned;

    public Task InvokeAsync(HttpContext context)
    {
        if (Volatile.Read(ref warned) == 0
            && context.Request.Headers.ContainsKey("X-Forwarded-For")
            && IsLoopbackOrPrivate(context.Connection.RemoteIpAddress)
            && Interlocked.Exchange(ref warned, 1) == 0)
        {
            LogLikelyUnconfiguredProxy(logger);
        }

        return next(context);
    }

    internal static bool IsLoopbackOrPrivate(IPAddress? address)
    {
        if (address is null)
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254),
            AddressFamily.InterNetworkV6 => (bytes[0] & 0xFE) == 0xFC || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80),
            _ => false,
        };
    }

    [LoggerMessage(
        EventId = 5101,
        Level = LogLevel.Warning,
        Message = "Requests arrive from a loopback/private peer with X-Forwarded-For, but ForwardedHeaders:KnownProxies is empty: all clients share one rate-limit bucket. Configure KnownProxies, or set ForwardedHeaders:Direct=true if there is no proxy.")]
    private static partial void LogLikelyUnconfiguredProxy(ILogger logger);
}
