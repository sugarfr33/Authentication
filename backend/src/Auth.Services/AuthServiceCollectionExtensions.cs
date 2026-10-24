using Auth.DAL;
using Auth.Services.Passwords;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

        string connectionString = configuration.GetConnectionString("CentralAuth")
            ?? throw new InvalidOperationException("Connection string 'CentralAuth' is not configured.");

        services.AddDataAccess(connectionString);
        services.AddPasswordServices();

        return services;
    }

    /// <summary>Argon2id hasher and password policy, all singletons. Keeps any PasswordHashingOptions registered earlier.</summary>
    internal static IServiceCollection AddPasswordServices(this IServiceCollection services)
    {
        services.TryAddSingleton(new PasswordHashingOptions());
        services.AddSingleton<CommonPasswordList>();
        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.AddSingleton<IPasswordPolicy, PasswordPolicy>();

        return services;
    }
}
