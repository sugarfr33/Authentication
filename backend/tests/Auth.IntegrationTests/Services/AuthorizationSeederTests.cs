using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Accounts;
using Auth.Services.Authorization;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Services;

/// <summary>T16: the authorization seeder is idempotent, keeps custom grants, bootstraps an admin, and verified accounts get the User role.</summary>
public sealed class AuthorizationSeederTests : RepositoryTestBase, IAsyncDisposable
{
    private readonly CapturingEmailSender mailbox = new();
    private readonly string bootstrapEmail = "boot-" + Guid.NewGuid().ToString("N")[..10] + "@example.test";
    private readonly ServiceProvider services;

    public AuthorizationSeederTests(SqlServerDatabaseFixture database)
        : base(database)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CentralAuth"] = database.ConnectionString,
                ["Auth:Issuer"] = "https://auth.example.test",
            })
            .Build();
        ServiceCollection collection = new();
        collection.AddSingleton(new PasswordHashingOptions { MemorySizeKiB = 1024, Iterations = 1, Parallelism = 1 });
        collection.AddSingleton<IEmailSender>(mailbox);
        collection.AddSingleton(new AuthorizationSeedOptions { BootstrapAdminEmail = bootstrapEmail });
        collection.AddAuthServices(configuration);
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    [Fact]
    public async Task Seeding_twice_adds_nothing_the_second_time_and_gives_Admin_every_permission()
    {
        await SeedAsync();

        AuthorizationSeedResult again = await SeedAsync();

        Assert.Equal((0, 0, 0), (again.PermissionsAdded, again.RolesAdded, again.GrantsAdded));
        List<string> codes = await WithContextAsync(c => c.Permission.AsNoTracking().Select(p => p.Code).ToListAsync());
        Assert.All(AuthPermissions.All, code => Assert.Single(codes, c => c == code));
        Role admin = await GlobalRoleAsync(AuthRoles.Admin);
        Role user = await GlobalRoleAsync(AuthRoles.User);
        Assert.True(admin.IsSystem && user.IsSystem);
        List<string> adminCodes = await WithContextAsync(c => c.RolePermission.AsNoTracking().Where(rp => rp.RoleId == admin.Id).Select(rp => rp.Permission.Code).ToListAsync());
        Assert.Equal(AuthPermissions.All.Order(StringComparer.Ordinal), adminCodes.Order(StringComparer.Ordinal));
        Assert.Empty(await WithContextAsync(c => c.RolePermission.AsNoTracking().Where(rp => rp.RoleId == user.Id).ToListAsync()));
    }

    [Fact]
    public async Task Seeding_keeps_grants_an_administrator_added()
    {
        await SeedAsync();
        Role user = await GlobalRoleAsync(AuthRoles.User);
        Permission read = await WithContextAsync(c => c.Permission.AsNoTracking().SingleAsync(p => p.Code == AuthPermissions.UsersRead));
        await SeedAsync(new RolePermission { RoleId = user.Id, PermissionId = read.Id });

        await SeedAsync();

        Assert.Single(await WithContextAsync(c => c.RolePermission.AsNoTracking().Where(rp => rp.RoleId == user.Id).ToListAsync()));
        await WithContextAsync(c => c.RolePermission.Where(rp => rp.RoleId == user.Id).ExecuteDeleteAsync());
    }

    [Fact]
    public async Task The_bootstrap_admin_is_assigned_only_when_verified_and_audited()
    {
        Role admin = await NoAdministratorsAsync();
        User account = await BootstrapAccountAsync(verified: false);

        Assert.Equal(BootstrapAdminOutcome.AccountNotEligible, (await SeedAsync()).Bootstrap);
        await WithContextAsync(c => c.User.Where(u => u.Id == account.Id).ExecuteUpdateAsync(s => s.SetProperty(u => u.EmailVerified, true)));
        Assert.Equal(BootstrapAdminOutcome.Assigned, (await SeedAsync()).Bootstrap);
        Assert.Equal(BootstrapAdminOutcome.AdministratorExists, (await SeedAsync()).Bootstrap);

        Assert.Single(await WithContextAsync(c => c.UserRole.AsNoTracking().Where(ur => ur.UserId == account.Id && ur.RoleId == admin.Id).ToListAsync()));
        AuditLog audit = Assert.Single(await WithContextAsync(c => c.AuditLog.AsNoTracking()
            .Where(a => a.UserId == account.Id && a.EventType == nameof(AuditEventType.RoleAssigned) && a.Detail!.Contains("bootstrap")).ToListAsync()));
        Assert.Equal("""{"role":"Admin","source":"bootstrap"}""", audit.Detail);
    }

    /// <summary>Reviewer MEDIUM-1 / audit MEDIUM-2: a configured email never restores a role an administrator took away.</summary>
    [Fact]
    public async Task A_demoted_bootstrap_admin_is_not_restored_while_another_admin_exists()
    {
        Role admin = await NoAdministratorsAsync();
        User account = await BootstrapAccountAsync(verified: true);
        Assert.True((await SeedAsync()).BootstrapAdminAssigned);
        User other = TestData.User();
        other.EmailVerified = true;
        await SeedAsync(other, new UserRole { UserId = other.Id, RoleId = admin.Id, AssignedUtc = TestData.Now });

        await WithContextAsync(c => c.UserRole.Where(ur => ur.UserId == account.Id && ur.RoleId == admin.Id).ExecuteDeleteAsync());
        AuthorizationSeedResult reseed = await SeedAsync();

        Assert.Equal(BootstrapAdminOutcome.AdministratorExists, reseed.Bootstrap);
        Assert.Empty(await WithContextAsync(c => c.UserRole.AsNoTracking().Where(ur => ur.UserId == account.Id && ur.RoleId == admin.Id).ToListAsync()));

        // Recovery (documented): only when no active, verified administrator is left does the setting apply again.
        await WithContextAsync(c => c.User.Where(u => u.Id == other.Id).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false)));
        Assert.Equal(BootstrapAdminOutcome.Assigned, (await SeedAsync()).Bootstrap);
    }

    /// <summary>Reviewer LOW a / audit LOW-1: accounts verified while the User role was missing receive it later.</summary>
    [Fact]
    public async Task Seeding_gives_the_User_role_to_verified_active_accounts_that_lack_it()
    {
        await SeedAsync();
        User verified = TestData.User();
        verified.EmailVerified = true;
        User unverified = TestData.User();
        User inactive = TestData.User();
        inactive.EmailVerified = true;
        inactive.IsActive = false;
        await SeedAsync(verified, unverified, inactive);

        for (int run = 0; run < 100 && (await SeedAsync()).UsersBackfilled > 0; run++)
        {
        }

        Role user = await GlobalRoleAsync(AuthRoles.User);
        List<Guid> holders = await WithContextAsync(c => c.UserRole.AsNoTracking()
            .Where(ur => ur.RoleId == user.Id && (ur.UserId == verified.Id || ur.UserId == unverified.Id || ur.UserId == inactive.Id))
            .Select(ur => ur.UserId).ToListAsync());
        Assert.Equal([verified.Id], holders);
        Assert.Equal(0, (await SeedAsync()).UsersBackfilled);
    }

    [Fact]
    public async Task Verifying_an_email_gives_the_account_the_User_role()
    {
        await SeedAsync();
        string email = "verified-" + Guid.NewGuid().ToString("N")[..10] + "@example.test";
        await InAppScopeAsync<IRegistrationService, RegistrationResult>(s => s.RegisterAsync(new RegisterRequest(email, "violet-canyon-7319", "Role Tester"), AuditContext.None, Ct));
        string body = mailbox.OnlyTo(email).Body;
        int start = body.IndexOf("#token=", StringComparison.Ordinal) + "#token=".Length;
        string token = new([.. body[start..].TakeWhile(c => char.IsLetterOrDigit(c) || c is '-' or '_')]);

        Assert.True((await InAppScopeAsync<IRegistrationService, Auth.Contracts.Result>(s => s.VerifyEmailAsync(token, AuditContext.None, Ct))).IsSuccess);

        Guid userId = (await WithContextAsync(c => c.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)))).Id;
        Role user = await GlobalRoleAsync(AuthRoles.User);
        Assert.Single(await WithContextAsync(c => c.UserRole.AsNoTracking().Where(ur => ur.UserId == userId && ur.RoleId == user.Id).ToListAsync()));
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    /// <summary>The bootstrap rule looks at the whole table, so these tests start with no Admin holders (shared test database).</summary>
    private async Task<Role> NoAdministratorsAsync()
    {
        await SeedAsync();
        Role admin = await GlobalRoleAsync(AuthRoles.Admin);
        await WithContextAsync(c => c.UserRole.Where(ur => ur.RoleId == admin.Id).ExecuteDeleteAsync());
        return admin;
    }

    private async Task<User> BootstrapAccountAsync(bool verified)
    {
        User account = TestData.User();
        account.Email = bootstrapEmail;
        account.NormalizedEmail = EmailNormalizer.Normalize(bootstrapEmail)!;
        account.EmailVerified = verified;
        await SeedAsync(account);
        return account;
    }

    private Task<AuthorizationSeedResult> SeedAsync() => InAppScopeAsync<IAuthorizationSeeder, AuthorizationSeedResult>(s => s.SeedAsync(Ct));

    private Task<Role> GlobalRoleAsync(string name)
    {
        string normalized = name.ToUpperInvariant();
        return WithContextAsync(c => c.Role.AsNoTracking().SingleAsync(r => r.ClientApplicationId == null && r.NormalizedName == normalized));
    }

    private async Task<TResult> InAppScopeAsync<TService, TResult>(Func<TService, Task<TResult>> action)
        where TService : notnull
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    private async Task<T> WithContextAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }
}
