using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.DAL;

public static class DataAccessServiceCollectionExtensions
{
    /// <summary>Registers the data-access layer: the internal AuthDbContext now, repositories and UoW in T04.</summary>
    public static IServiceCollection AddDataAccess(this IServiceCollection services, string connectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddDbContext<AuthDbContext>(options => options.UseSqlServer(connectionString));

        return services;
    }
}
