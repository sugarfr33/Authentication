using Auth.DAL;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Services;

public static class AuthServiceCollectionExtensions
{
    /// <summary>
    /// Single composition entry point for the host. Wires the data-access layer so Auth.Api never references Auth.DAL.
    /// </summary>
    public static IServiceCollection AddAuthServices(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var connectionString = configuration.GetConnectionString("CentralAuth")
            ?? throw new InvalidOperationException("Connection string 'CentralAuth' is not configured.");

        services.AddDataAccess(connectionString);

        return services;
    }
}
