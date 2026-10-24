using Auth.DAL;

namespace Auth.Services.Common;

/// <summary>Dependency checks for the readiness endpoint, so Auth.Api never touches the data-access layer.</summary>
public interface ISystemHealth
{
    Task<bool> IsDatabaseAvailableAsync(CancellationToken cancellationToken);
}

internal sealed class SystemHealth(IDatabaseHealthProbe database) : ISystemHealth
{
    public Task<bool> IsDatabaseAvailableAsync(CancellationToken cancellationToken) => database.CanConnectAsync(cancellationToken);
}
