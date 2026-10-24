using Auth.Services.Common;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Auth.Api.Health;

/// <summary>Readiness: can the database be reached within a few seconds? Reports no connection or error details.</summary>
internal sealed class DatabaseReadinessCheck(ISystemHealth health) : IHealthCheck
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);

        bool available = await health.IsDatabaseAvailableAsync(timeout.Token);
        return available ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy();
    }
}
