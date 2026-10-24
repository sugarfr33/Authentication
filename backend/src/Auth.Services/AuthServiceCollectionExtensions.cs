using Auth.DAL;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Tokens;
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
        services.AddScoped<ISystemHealth, SystemHealth>();
        services.AddTokenServices(configuration);

        return services;
    }

    /// <summary>
    /// Clock, secret store, signing-key provider (singleton) and rotation (scoped). Keeps any IClock, ISecretStore or
    /// TokenOptions registered earlier. TokenOptions.Issuer comes from Auth:Issuer and is checked when first resolved.
    /// </summary>
    internal static IServiceCollection AddTokenServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.TryAddSingleton<IClock, SystemClock>();
        services.TryAddSingleton<ISecretStore>(new ConfigurationSecretStore(configuration));
        services.TryAddSingleton(_ => new TokenOptions
        {
            Issuer = configuration["Auth:Issuer"] ?? throw new InvalidOperationException("Configuration value 'Auth:Issuer' is missing."),
            Audience = configuration["Auth:Audience"],
        }.Validated());
        services.AddSingleton<SigningKeyProvider>();
        services.AddSingleton<ISigningKeyProvider>(sp => sp.GetRequiredService<SigningKeyProvider>());
        services.AddScoped<ISigningKeyRotation, SigningKeyRotation>();
        services.AddSingleton<ITokenService, TokenService>();
        services.TryAddSingleton(new RefreshTokenOptions().Validated());
        services.AddSingleton<ITokenGenerator, TokenGenerator>();
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();

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
