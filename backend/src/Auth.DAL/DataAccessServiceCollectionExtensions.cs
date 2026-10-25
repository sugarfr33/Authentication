using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.DAL;

public static class DataAccessServiceCollectionExtensions
{
    /// <summary>Registers the data-access layer: the internal AuthDbContext, repositories and unit of work, all scoped.</summary>
    public static IServiceCollection AddDataAccess(this IServiceCollection services, string connectionString) =>
        AddDataAccess(services, connectionString, configureOptions: null);

    /// <summary>Test hook: lets integration tests add EF options such as a command interceptor.</summary>
    internal static IServiceCollection AddDataAccess(
        this IServiceCollection services,
        string connectionString,
        Action<DbContextOptionsBuilder>? configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddDbContext<AuthDbContext>(options =>
        {
            AuthDbContext.UseAuthSqlServer(options, connectionString);
            configureOptions?.Invoke(options);
        });

        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IDatabaseHealthProbe, DatabaseHealthProbe>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IClientApplicationRepository, ClientApplicationRepository>();
        services.AddScoped<ISigningKeyRepository, SigningKeyRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        services.AddScoped<IRetentionRepository, RetentionRepository>();
        services.AddScoped<IAuthorizationCodeRepository, AuthorizationCodeRepository>();
        services.AddScoped<IOneTimeTokenRepository<PasswordResetToken>>(sp =>
            new OneTimeTokenRepository<PasswordResetToken>(sp.GetRequiredService<AuthDbContext>(), nameof(PasswordResetToken.TokenHash)));
        services.AddScoped<IOneTimeTokenRepository<EmailVerificationToken>>(sp =>
            new OneTimeTokenRepository<EmailVerificationToken>(
                sp.GetRequiredService<AuthDbContext>(),
                nameof(EmailVerificationToken.TokenHash),
                nameof(EmailVerificationToken.PendingPasswordHash),
                nameof(EmailVerificationToken.PendingDisplayName)));
        services.AddScoped<IOneTimeTokenRepository<MfaRecoveryCode>>(sp =>
            new OneTimeTokenRepository<MfaRecoveryCode>(sp.GetRequiredService<AuthDbContext>(), nameof(MfaRecoveryCode.CodeHash)));

        return services;
    }
}
