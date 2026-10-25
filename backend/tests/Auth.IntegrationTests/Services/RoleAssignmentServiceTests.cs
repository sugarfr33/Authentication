using Auth.Contracts;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Accounts;
using Auth.Services.Authorization;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Services;

/// <summary>Audit MEDIUM-3: taking a role or a permission away ends the affected sessions instead of waiting for token expiry.</summary>
public sealed class RoleAssignmentServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private readonly ServiceProvider services;

    public RoleAssignmentServiceTests(SqlServerDatabaseFixture database)
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
        collection.AddSingleton(new SessionLivenessOptions { CacheDuration = TimeSpan.FromSeconds(30) });
        collection.AddSingleton<IEmailSender>(new CapturingEmailSender());
        collection.AddAuthServices(configuration);
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    [Fact]
    public async Task Removing_a_role_ends_every_session_of_that_user_at_once_and_is_audited()
    {
        (User user, Role role, RefreshToken first, RefreshToken second) = await HolderWithTwoSessionsAsync();
        RefreshToken bystander = await LiveSessionAsync(TestData.User());
        ISessionLiveness liveness = services.GetRequiredService<ISessionLiveness>();
        Assert.True(await liveness.IsLiveAsync(user.Id, first.FamilyId, Ct));
        Assert.True(await liveness.IsLiveAsync(bystander.UserId, bystander.FamilyId, Ct));

        bool removed = await InAppScopeAsync<IRoleAssignmentService, bool>(s => s.RemoveUserRoleAsync(user.Id, role.Id, AuditContext.None, Ct));

        // The cache holds "live" for 30 s here: a false answer now proves the same-instance invalidation.
        Assert.True(removed);
        Assert.False(await liveness.IsLiveAsync(user.Id, first.FamilyId, Ct));
        Assert.False(await liveness.IsLiveAsync(user.Id, second.FamilyId, Ct));
        Assert.True(await liveness.IsLiveAsync(bystander.UserId, bystander.FamilyId, Ct));
        Assert.Empty(await WithContextAsync(c => c.UserRole.AsNoTracking().Where(ur => ur.UserId == user.Id).ToListAsync()));
        Assert.All(await TokensAsync(user.Id), t => Assert.Equal(RefreshTokenRevokedReason.Admin, t.RevokedReason));
        AuditLog audit = Assert.Single(await AuditAsync(AuditEventType.RoleRemoved, user.Id));
        Assert.Equal("{\"role\":\"" + role.Id.ToString("D") + "\"}", audit.Detail);
    }

    [Fact]
    public async Task Removing_a_permission_from_a_role_ends_the_sessions_of_every_holder_only()
    {
        (User user, Role role, RefreshToken first, _) = await HolderWithTwoSessionsAsync();
        Permission permission = TestData.Permission();
        await SeedAsync(permission, new RolePermission { RoleId = role.Id, PermissionId = permission.Id });
        User otherHolder = TestData.User();
        RefreshToken otherSession = await LiveSessionAsync(otherHolder, new UserRole { UserId = otherHolder.Id, RoleId = role.Id, AssignedUtc = TestData.Now });
        RefreshToken outsiderSession = await LiveSessionAsync(TestData.User());
        ISessionLiveness liveness = services.GetRequiredService<ISessionLiveness>();
        Assert.True(await liveness.IsLiveAsync(user.Id, first.FamilyId, Ct));

        bool removed = await InAppScopeAsync<IRoleAssignmentService, bool>(s => s.RemoveRolePermissionAsync(role.Id, permission.Id, AuditContext.None, Ct));

        Assert.True(removed);
        Assert.False(await liveness.IsLiveAsync(user.Id, first.FamilyId, Ct));
        Assert.False(await liveness.IsLiveAsync(otherHolder.Id, otherSession.FamilyId, Ct));
        Assert.True(await liveness.IsLiveAsync(outsiderSession.UserId, outsiderSession.FamilyId, Ct));
        Assert.Empty(await WithContextAsync(c => c.RolePermission.AsNoTracking().Where(rp => rp.RoleId == role.Id).ToListAsync()));
        string detail = "{\"role\":\"" + role.Id.ToString("D") + "\",\"permission\":\"" + permission.Id.ToString("D") + "\"}";
        Assert.Single(await WithContextAsync(c => c.AuditLog.AsNoTracking()
            .Where(a => a.EventType == nameof(AuditEventType.RolePermissionRemoved) && a.Detail == detail).ToListAsync()));
    }

    [Fact]
    public async Task Removing_what_is_not_there_changes_nothing()
    {
        (User user, Role role, _, _) = await HolderWithTwoSessionsAsync();

        Assert.False(await InAppScopeAsync<IRoleAssignmentService, bool>(s => s.RemoveUserRoleAsync(user.Id, Guid.NewGuid(), AuditContext.None, Ct)));
        Assert.False(await InAppScopeAsync<IRoleAssignmentService, bool>(s => s.RemoveRolePermissionAsync(role.Id, Guid.NewGuid(), AuditContext.None, Ct)));

        Assert.All(await TokensAsync(user.Id), t => Assert.Null(t.RevokedUtc));
        Assert.Empty(await AuditAsync(AuditEventType.RoleRemoved, user.Id));
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private async Task<(User User, Role Role, RefreshToken First, RefreshToken Second)> HolderWithTwoSessionsAsync()
    {
        User user = TestData.User();
        Role role = TestData.Role();
        await SeedAsync(role);
        RefreshToken first = await LiveSessionAsync(user, new UserRole { UserId = user.Id, RoleId = role.Id, AssignedUtc = TestData.Now });
        RefreshToken second = Live(user.Id);
        await SeedAsync(second);
        return (user, role, first, second);
    }

    private async Task<RefreshToken> LiveSessionAsync(User user, params object[] extra)
    {
        RefreshToken session = Live(user.Id);
        await SeedAsync([user, .. extra, session]);
        return session;
    }

    private static RefreshToken Live(Guid userId) =>
        TestData.RefreshToken(userId, expiresUtc: DateTime.UtcNow.AddDays(1), createdUtc: DateTime.UtcNow.AddMinutes(-1));

    private Task<List<RefreshToken>> TokensAsync(Guid userId) =>
        WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync());

    private Task<List<AuditLog>> AuditAsync(AuditEventType type, Guid userId)
    {
        string name = type.ToString();
        return WithContextAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == userId && a.EventType == name).ToListAsync());
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
