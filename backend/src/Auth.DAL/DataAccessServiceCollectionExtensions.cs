using Microsoft.Extensions.DependencyInjection;

namespace Auth.DAL;

public static class DataAccessServiceCollectionExtensions
{
    /// <summary>Registers the data-access layer. AuthDbContext, repositories and UoW are added in T03/T04.</summary>
    public static IServiceCollection AddDataAccess(this IServiceCollection services, string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        return services;
    }
}
