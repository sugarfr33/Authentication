using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Auth.Client;

/// <summary>Registers central-auth token validation for a resource server (docs/t22-client-extension.md).</summary>
public static class CentralAuthServiceCollectionExtensions
{
    /// <summary>Adds authentication with the <see cref="CentralAuthDefaults.AuthenticationScheme"/> scheme as the default, bound to <paramref name="section"/>.</summary>
    public static AuthenticationBuilder AddCentralAuth(this IServiceCollection services, IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        return services.AddCentralAuth(section.Bind);
    }

    /// <summary>Adds authentication with the <see cref="CentralAuthDefaults.AuthenticationScheme"/> scheme as the default.</summary>
    public static AuthenticationBuilder AddCentralAuth(this IServiceCollection services, Action<CentralAuthOptions> configure) =>
        services.AddAuthentication(CentralAuthDefaults.AuthenticationScheme).AddCentralAuth(CentralAuthDefaults.AuthenticationScheme, configure);

    /// <summary>Adds a central-auth scheme under <paramref name="scheme"/> (each scheme has its own options and JWKS cache).</summary>
    public static AuthenticationBuilder AddCentralAuth(this AuthenticationBuilder builder, string scheme, Action<CentralAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<JwksCacheRegistry>();
        // Never follow a redirect: an open redirect on the issuer host must not hand the client an attacker's JWKS.
        builder.Services.AddHttpClient(CentralAuthDefaults.JwksHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CentralAuthOptions>, CentralAuthPostConfigure>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<CentralAuthOptions>, CentralAuthOptionsValidator>());
        builder.Services.AddOptions<CentralAuthOptions>(scheme).ValidateOnStart();
        return builder.AddScheme<CentralAuthOptions, CentralAuthHandler>(scheme, configure);
    }
}
