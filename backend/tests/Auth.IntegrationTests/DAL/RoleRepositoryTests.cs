using Auth.DAL.Repositories;
using Auth.Entities;

namespace Auth.IntegrationTests.DAL;

public class RoleRepositoryTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public async Task Roles_are_global_ones_plus_those_of_the_requested_application()
    {
        Scenario s = await SeedScenarioAsync();

        IReadOnlyList<Role> forApp = await InScopeAsync<IRoleRepository, IReadOnlyList<Role>>(r => r.GetForUserAsync(s.User.Id, s.App.Id, Ct));
        IReadOnlyList<Role> globalOnly = await InScopeAsync<IRoleRepository, IReadOnlyList<Role>>(r => r.GetForUserAsync(s.User.Id, null, Ct));

        Assert.Equal(new[] { s.GlobalRole.Id, s.AppRole.Id }.Order(), forApp.Select(r => r.Id).Order());
        Assert.Equal([s.GlobalRole.Id], globalOnly.Select(r => r.Id));
    }

    [Fact]
    public async Task Permission_codes_are_distinct_and_limited_to_the_applicable_roles()
    {
        Scenario s = await SeedScenarioAsync();

        IReadOnlyList<string> codes = await InScopeAsync<IRoleRepository, IReadOnlyList<string>>(
            r => r.GetPermissionCodesForUserAsync(s.User.Id, s.App.Id, Ct));

        Assert.Equal(new[] { s.Shared.Code, s.AppOnly.Code }.Order(StringComparer.Ordinal), codes);
    }

    [Fact]
    public async Task User_without_roles_gets_empty_lists()
    {
        User user = TestData.User();
        await SeedAsync(user);

        Assert.Empty(await InScopeAsync<IRoleRepository, IReadOnlyList<Role>>(r => r.GetForUserAsync(user.Id, null, Ct)));
        Assert.Empty(await InScopeAsync<IRoleRepository, IReadOnlyList<string>>(r => r.GetPermissionCodesForUserAsync(user.Id, null, Ct)));
    }

    /// <summary>
    /// The user holds a global role, a role of App and a role of OtherApp. Shared is granted by both the global and the
    /// App role (so it must be de-duplicated); AppOnly by the App role; OtherOnly only by the OtherApp role.
    /// </summary>
    private async Task<Scenario> SeedScenarioAsync()
    {
        User user = TestData.User();
        ClientApplication app = TestData.ClientApplication();
        ClientApplication otherApp = TestData.ClientApplication();
        Role globalRole = TestData.Role();
        Role appRole = TestData.Role(app.Id);
        Role otherAppRole = TestData.Role(otherApp.Id);
        Permission shared = TestData.Permission();
        Permission appOnly = TestData.Permission();
        Permission otherOnly = TestData.Permission();

        await SeedAsync(
            user, app, otherApp, globalRole, appRole, otherAppRole, shared, appOnly, otherOnly,
            new UserRole { UserId = user.Id, RoleId = globalRole.Id, AssignedUtc = TestData.Now },
            new UserRole { UserId = user.Id, RoleId = appRole.Id, AssignedUtc = TestData.Now },
            new UserRole { UserId = user.Id, RoleId = otherAppRole.Id, AssignedUtc = TestData.Now },
            new RolePermission { RoleId = globalRole.Id, PermissionId = shared.Id },
            new RolePermission { RoleId = appRole.Id, PermissionId = shared.Id },
            new RolePermission { RoleId = appRole.Id, PermissionId = appOnly.Id },
            new RolePermission { RoleId = otherAppRole.Id, PermissionId = otherOnly.Id });

        return new Scenario(user, app, globalRole, appRole, shared, appOnly);
    }

    private sealed record Scenario(User User, ClientApplication App, Role GlobalRole, Role AppRole, Permission Shared, Permission AppOnly);
}
