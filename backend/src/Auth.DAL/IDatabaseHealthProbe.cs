using Microsoft.EntityFrameworkCore;

namespace Auth.DAL;

/// <summary>Readiness probe for the CentralAuth database. Never throws and never exposes connection details.</summary>
public interface IDatabaseHealthProbe
{
    /// <summary>True when a connection can be opened and the database answers.</summary>
    Task<bool> CanConnectAsync(CancellationToken cancellationToken);
}

internal sealed class DatabaseHealthProbe(AuthDbContext context) : IDatabaseHealthProbe
{
    public async Task<bool> CanConnectAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await context.Database.CanConnectAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
