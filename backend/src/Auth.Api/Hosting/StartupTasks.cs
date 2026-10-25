using System.Net;
using System.Net.Sockets;
using Auth.Services.Authorization;
using Auth.Services.ClientApplications;
using Auth.Services.Retention;
using Auth.Services.Security;

namespace Auth.Api.Hosting;

/// <summary>
/// Creates the timing guard's dummy hash at startup, outside any request, so the first unknown-account sign-in does
/// not pay for an extra Hash (audit LOW-5). It never stops the host: any failure is logged as a warning and the guard
/// simply creates the hash on first need.
/// </summary>
internal sealed partial class TimingGuardWarmUp(IAuthTimingGuard guard, ILogger<TimingGuardWarmUp> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await guard.WarmUpAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutting down before the warm-up finished: nothing to report.
        }
        catch (Exception ex)
        {
            LogWarmUpFailed(logger, ex);
        }
    }

    [LoggerMessage(EventId = 5100, Level = LogLevel.Warning, Message = "Timing-guard warm-up failed; the dummy hash will be created on first use")]
    private static partial void LogWarmUpFailed(ILogger logger, Exception exception);
}

/// <summary>
/// Seeds the system permissions and roles at startup (idempotent; T16). A failure is logged and never stops the host:
/// existing authorization data keeps working, and the next start tries again.
/// </summary>
internal sealed partial class AuthorizationSeedOnStartup(
    IServiceScopeFactory scopes,
    AuthorizationSeedOptions options,
    ILogger<AuthorizationSeedOnStartup> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.SeedOnStartup)
        {
            return;
        }

        try
        {
            await using AsyncServiceScope scope = scopes.CreateAsyncScope();
            AuthorizationSeedResult result = await scope.ServiceProvider.GetRequiredService<IAuthorizationSeeder>().SeedAsync(stoppingToken);
            LogSeeded(logger, result.PermissionsAdded, result.RolesAdded, result.GrantsAdded, result.UsersBackfilled, result.BootstrapAdminAssigned);
            if (result.Bootstrap == BootstrapAdminOutcome.AdministratorExists)
            {
                LogBootstrapIgnored(logger);
            }
            else if (result.Bootstrap == BootstrapAdminOutcome.AccountNotEligible)
            {
                LogBootstrapNotEligible(logger);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            LogSeedFailed(logger, ex.GetType().Name);
        }
    }

    [LoggerMessage(EventId = 5400, Level = LogLevel.Information, Message = "Authorization seed: {Permissions} permission(s), {Roles} role(s), {Grants} grant(s) added, User role given to {Backfilled} account(s); bootstrap admin assigned: {Bootstrap}")]
    private static partial void LogSeeded(ILogger logger, int permissions, int roles, int grants, int backfilled, bool bootstrap);

    [LoggerMessage(EventId = 5402, Level = LogLevel.Warning, Message = "Authorization:BootstrapAdminEmail is set but an administrator already exists, so it was ignored; remove the setting")]
    private static partial void LogBootstrapIgnored(ILogger logger);

    [LoggerMessage(EventId = 5403, Level = LogLevel.Warning, Message = "Authorization:BootstrapAdminEmail matches no active account with a verified email; no administrator was assigned")]
    private static partial void LogBootstrapNotEligible(ILogger logger);

    [LoggerMessage(EventId = 5401, Level = LogLevel.Warning, Message = "Authorization seed failed ({ExceptionType}); existing roles and permissions are unchanged")]
    private static partial void LogSeedFailed(ILogger logger, string exceptionType);
}

/// <summary>
/// Registers the configured bootstrap client application (ClientApplications:Bootstrap, usually the SPA) when no
/// application exists yet (T18). Idempotent and safe on several instances; a failure is logged and never stops the host.
/// </summary>
internal sealed partial class ClientApplicationSeedOnStartup(
    IServiceScopeFactory scopes,
    ClientApplicationBootstrapOptions options,
    ILogger<ClientApplicationSeedOnStartup> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.IsConfigured)
        {
            return;
        }

        try
        {
            await using AsyncServiceScope scope = scopes.CreateAsyncScope();
            ClientApplicationBootstrapOutcome outcome = await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().BootstrapAsync(options, stoppingToken);
            if (outcome == ClientApplicationBootstrapOutcome.Invalid)
            {
                LogBootstrapInvalid(logger);
            }
            else
            {
                LogBootstrap(logger, outcome);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            LogBootstrapFailed(logger, ex.GetType().Name);
        }
    }

    [LoggerMessage(EventId = 5420, Level = LogLevel.Information, Message = "Client application bootstrap: {Outcome}")]
    private static partial void LogBootstrap(ILogger logger, ClientApplicationBootstrapOutcome outcome);

    [LoggerMessage(EventId = 5421, Level = LogLevel.Warning, Message = "ClientApplications:Bootstrap is invalid (see docs/client-applications.md); no application was registered")]
    private static partial void LogBootstrapInvalid(ILogger logger);

    [LoggerMessage(EventId = 5422, Level = LogLevel.Warning, Message = "Client application bootstrap failed ({ExceptionType}); it runs again at the next start")]
    private static partial void LogBootstrapFailed(ILogger logger, string exceptionType);
}

/// <summary>
/// Runs the retention purge every RetentionOptions.Interval when Retention:Enabled is true (T17). A failed run is
/// logged with the exception type only and retried at the next interval; it never stops the host.
/// </summary>
internal sealed partial class RetentionPurgeService(
    IServiceScopeFactory scopes,
    RetentionOptions options,
    TimeProvider time,
    IHostEnvironment environment,
    ILogger<RetentionPurgeService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled)
        {
            // T17 audit MEDIUM-2: without the purge, unauthenticated events (failed logins, sign-ups, reset requests)
            // grow the audit table without bound. Production must enable it.
            if (!environment.IsDevelopment())
            {
                LogRetentionDisabled(logger);
            }

            return;
        }

        using PeriodicTimer timer = new(options.Validated().Interval, time);
        do
        {
            try
            {
                await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                RetentionPurgeResult result = await scope.ServiceProvider.GetRequiredService<IRetentionPurge>().PurgeAsync(stoppingToken);
                LogPurged(logger, result.PendingRegistrationsErased, result.EmailVerificationTokensDeleted, result.PasswordResetTokensDeleted, result.AuthorizationCodesDeleted, result.RefreshTokensDeleted, result.AuditRowsDeleted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                LogPurgeFailed(logger, ex.GetType().Name);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    [LoggerMessage(EventId = 5410, Level = LogLevel.Information, Message = "Retention purge: {Erased} pending registration(s) erased; deleted {Verification} verification link(s), {Reset} reset link(s), {Codes} authorization code(s), {Refresh} refresh token row(s), {Audit} audit row(s)")]
    private static partial void LogPurged(ILogger logger, int erased, int verification, int reset, int codes, int refresh, int audit);

    [LoggerMessage(EventId = 5412, Level = LogLevel.Warning, Message = "Retention:Enabled is false: audit rows and spent tokens are never deleted and the audit table grows without bound; enable it in production")]
    private static partial void LogRetentionDisabled(ILogger logger);

    [LoggerMessage(EventId = 5411, Level = LogLevel.Warning, Message = "Retention purge failed ({ExceptionType}); it runs again at the next interval")]
    private static partial void LogPurgeFailed(ILogger logger, string exceptionType);
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
