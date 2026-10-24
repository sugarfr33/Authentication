using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.UnitTests.DAL;

/// <summary>AddDataAccess wiring and exception mapping helpers; no database needed.</summary>
public class DataAccessRegistrationTests
{
    private static readonly Type[] PublicServices =
    [
        typeof(IUnitOfWork),
        typeof(IUserRepository),
        typeof(IRoleRepository),
        typeof(IRefreshTokenRepository),
        typeof(IOneTimeTokenRepository<PasswordResetToken>),
        typeof(IOneTimeTokenRepository<EmailVerificationToken>),
        typeof(IOneTimeTokenRepository<MfaRecoveryCode>),
        typeof(IClientApplicationRepository),
        typeof(ISigningKeyRepository),
        typeof(IAuditLogRepository),
    ];

    [Fact]
    public void Every_repository_and_the_unit_of_work_are_registered_scoped()
    {
        ServiceCollection services = new();
        services.AddDataAccess("Server=unused;Database=unused");

        IEnumerable<string> problems = PublicServices
            .Select(type => (type, descriptor: services.SingleOrDefault(d => d.ServiceType == type)))
            .Where(x => x.descriptor?.Lifetime != ServiceLifetime.Scoped)
            .Select(x => x.type.Name + ": " + (x.descriptor?.Lifetime.ToString() ?? "missing"));

        Assert.Empty(problems);
    }

    [Fact]
    public async Task Repositories_in_one_scope_share_the_unit_of_work_context()
    {
        ServiceCollection services = new();
        services.AddDataAccess("Server=unused;Database=unused");
        await using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        await using AsyncServiceScope scope = provider.CreateAsyncScope();

        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        User user = new() { Id = Guid.NewGuid() };
        await scope.ServiceProvider.GetRequiredService<IUserRepository>().AddAsync(user, CancellationToken.None);

        Assert.Contains(context.ChangeTracker.Entries<User>(), e => e.Entity == user);
        Assert.All(PublicServices, type => Assert.NotNull(scope.ServiceProvider.GetRequiredService(type)));
    }

    [Theory]
    [InlineData(
        "Cannot insert duplicate key row in object 'auth.User' with unique index 'UQ_User_NormalizedEmail'. The duplicate key value is (A@B.C).",
        "UQ_User_NormalizedEmail")]
    [InlineData(
        "Violation of PRIMARY KEY constraint 'PK_UserRole'. Cannot insert duplicate key in object 'auth.UserRole'.",
        "PK_UserRole")]
    [InlineData("Some other database error.", null)]
    public void Constraint_name_is_parsed_from_the_SQL_Server_message(string message, string? expected)
    {
        Assert.Equal(expected, UnitOfWork.ParseConstraintName(message));
    }
}
