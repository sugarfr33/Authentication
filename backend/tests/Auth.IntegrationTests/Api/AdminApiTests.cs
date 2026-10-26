using System.Net;
using System.Text;
using System.Text.Json;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Admin;
using Auth.Services.Authorization;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T21b: the admin API through the real pipeline. A test per policy (each endpoint answers 403 without its permission),
/// a test per audit row (with the acting administrator), the guard rails (last administrator, self-lockout, the Admin
/// role's permissions), session revocation, CORS invalidation, CSRF, JSON-only, caps and no secrets in answers.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class AdminApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Admin = "/api/v1/admin";
    private const string Login = "/api/v1/auth/login";
    private const string Me = "/api/v1/auth/me";
    private const string Password = "amber-harbor-4826";

    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    /// <summary>Every admin endpoint and the one permission it needs. Ids are random: allowed callers get 404 or 400, never 403.</summary>
    private static readonly (string Method, string Path, string Policy, object? Body)[] Endpoints =
    [
        ("GET", Admin + "/users", AuthPolicies.UsersRead, null),
        ("GET", Admin + "/users/" + Guid.NewGuid(), AuthPolicies.UsersRead, null),
        ("POST", Admin + "/users/" + Guid.NewGuid() + "/deactivate", AuthPolicies.UsersWrite, null),
        ("POST", Admin + "/users/" + Guid.NewGuid() + "/reactivate", AuthPolicies.UsersWrite, null),
        ("POST", Admin + "/users/" + Guid.NewGuid() + "/mfa/reset", AuthPolicies.UsersWrite, null),
        ("GET", Admin + "/roles", AuthPolicies.RolesManage, null),
        ("GET", Admin + "/permissions", AuthPolicies.RolesManage, null),
        ("POST", Admin + "/users/" + Guid.NewGuid() + "/roles", AuthPolicies.RolesManage, new AdminRoleAssignmentRequest(Guid.NewGuid())),
        ("DELETE", Admin + "/users/" + Guid.NewGuid() + "/roles/" + Guid.NewGuid(), AuthPolicies.RolesManage, null),
        ("POST", Admin + "/roles/" + Guid.NewGuid() + "/permissions", AuthPolicies.RolesManage, new AdminPermissionGrantRequest(Guid.NewGuid())),
        ("DELETE", Admin + "/roles/" + Guid.NewGuid() + "/permissions/" + Guid.NewGuid(), AuthPolicies.RolesManage, null),
        ("GET", Admin + "/apps", AuthPolicies.AppsManage, null),
        ("GET", Admin + "/apps/" + Guid.NewGuid(), AuthPolicies.AppsManage, null),
        ("POST", Admin + "/apps", AuthPolicies.AppsManage, new { clientId = "" }),
        ("PUT", Admin + "/apps/" + Guid.NewGuid(), AuthPolicies.AppsManage, new { clientId = "" }),
        ("POST", Admin + "/apps/" + Guid.NewGuid() + "/activate", AuthPolicies.AppsManage, null),
        ("POST", Admin + "/apps/" + Guid.NewGuid() + "/deactivate", AuthPolicies.AppsManage, null),
        ("GET", Admin + "/audit", AuthPolicies.AuditRead, null),
    ];

    private readonly RecordingListener ended = new();
    private WebApplicationFactory<Program> app = null!;

    public async Task InitializeAsync()
    {
        app = WithSettings(new Dictionary<string, string?>
        {
            ["RateLimiting:Policies:Admin:PerIp:PermitLimit"] = "100000",
        });
        await EnsurePermissionRolesAsync();
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    public static TheoryData<string> Holders() => ["none", .. AuthPermissions.All.Where(p => p != AuthPermissions.SessionsManage)];

    [Theory]
    [MemberData(nameof(Holders))]
    public async Task Every_admin_endpoint_answers_403_without_its_permission(string holder)
    {
        (_, string email) = await SeedUserAsync(holder == "none" ? [AuthRoles.User] : [RoleFor(holder)]);
        using Browser browser = await SignedInAsync(email);

        foreach ((string method, string path, string policy, object? body) in Endpoints)
        {
            HttpResponseMessage response = await SendAsync(browser, method, path, body);
            string answer = await response.Content.ReadAsStringAsync();
            if (policy == holder)
            {
                Assert.True(response.StatusCode is not (HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized), method + " " + path + " refused its own permission holder");
            }
            else
            {
                Assert.True(response.StatusCode == HttpStatusCode.Forbidden, method + " " + path + " answered " + (int)response.StatusCode + " to " + holder);
                Assert.Contains("Access denied.", answer, StringComparison.Ordinal);
                Assert.DoesNotContain(policy, answer, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public async Task Without_a_session_every_admin_endpoint_answers_401()
    {
        using Browser anonymous = new(app);
        await anonymous.GetAsync(TestEndpoints.Prefix + "/ping");
        foreach ((string method, string path, _, object? body) in Endpoints)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(anonymous, method, path, body)).StatusCode);
        }
    }

    [Fact]
    public async Task Assigning_and_removing_a_role_is_audited_with_the_actor_and_removal_ends_the_sessions()
    {
        (Guid adminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid targetId, string targetEmail) = await SeedUserAsync([AuthRoles.User]);
        Guid auditorRole = await RoleIdAsync(RoleFor(AuthPermissions.AuditRead));
        using Browser admin = await SignedInAsync(adminEmail);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(auditorRole))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(auditorRole))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(Guid.NewGuid()))).StatusCode);
        AuditLog assigned = Assert.Single(await RowsAsync(AuditEventType.RoleAssigned, targetId));
        Assert.Equal($"{{\"role\":\"{auditorRole}\",\"source\":\"admin\",\"actor\":\"{adminId}\"}}", assigned.Detail);

        // The new role reaches the target's token at the next sign-in; removing it ends every session at once.
        using Browser target = await SignedInAsync(targetEmail);
        Assert.Equal(HttpStatusCode.OK, (await target.GetAsync(Admin + "/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "DELETE", Admin + "/users/" + targetId + "/roles/" + auditorRole, null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await target.GetAsync(Me)).StatusCode);
        AuditLog removed = Assert.Single(await RowsAsync(AuditEventType.RoleRemoved, targetId));
        Assert.Equal($"{{\"role\":\"{auditorRole}\",\"actor\":\"{adminId}\"}}", removed.Detail);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "DELETE", Admin + "/users/" + targetId + "/roles/" + auditorRole, null)).StatusCode);
        Assert.Single(await RowsAsync(AuditEventType.RoleRemoved, targetId));
    }

    [Fact]
    public async Task Granting_and_removing_a_permission_is_audited_and_removal_ends_the_holders_sessions()
    {
        (Guid adminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        Guid roleId = await CreateRoleAsync("Grant-" + Guid.NewGuid().ToString("N")[..8], []);
        Guid usersRead = await PermissionIdAsync(AuthPermissions.UsersRead);
        (Guid holderId, string holderEmail) = await SeedUserAsync([AuthRoles.User]);
        await AddRoleAsync(holderId, roleId);
        using Browser admin = await SignedInAsync(adminEmail);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/roles/" + roleId + "/permissions", new AdminPermissionGrantRequest(usersRead))).StatusCode);
        AuditLog granted = Assert.Single(await RowsAsync(AuditEventType.RolePermissionGranted, null), r => r.Detail!.Contains(roleId.ToString(), StringComparison.Ordinal));
        Assert.Equal($"{{\"role\":\"{roleId}\",\"permission\":\"{usersRead}\",\"actor\":\"{adminId}\"}}", granted.Detail);

        using Browser holder = await SignedInAsync(holderEmail);
        Assert.Equal(HttpStatusCode.OK, (await holder.GetAsync(Admin + "/users")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "DELETE", Admin + "/roles/" + roleId + "/permissions/" + usersRead, null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await holder.GetAsync(Me)).StatusCode);
        AuditLog removed = Assert.Single(await RowsAsync(AuditEventType.RolePermissionRemoved, null), r => r.Detail!.Contains(roleId.ToString(), StringComparison.Ordinal));
        Assert.Equal($"{{\"role\":\"{roleId}\",\"permission\":\"{usersRead}\",\"actor\":\"{adminId}\"}}", removed.Detail);
    }

    [Fact]
    public async Task Deactivating_a_user_ends_every_session_blocks_sign_in_and_reactivation_restores_it()
    {
        (Guid adminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid targetId, string targetEmail) = await SeedUserAsync([AuthRoles.User]);
        using Browser admin = await SignedInAsync(adminEmail);
        using Browser first = await SignedInAsync(targetEmail);
        using Browser second = await SignedInAsync(targetEmail);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/deactivate", null)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await first.GetAsync(Me)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await second.GetAsync(Me)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TrySignInAsync(targetEmail)).StatusCode);
        AuditLog deactivated = Assert.Single(await RowsAsync(AuditEventType.UserDeactivated, targetId));
        Assert.Equal($"{{\"revoked\":2,\"actor\":\"{adminId}\"}}", deactivated.Detail);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/deactivate", null)).StatusCode);
        Assert.Single(await RowsAsync(AuditEventType.UserDeactivated, targetId));

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/reactivate", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await TrySignInAsync(targetEmail)).StatusCode);
        AuditLog reactivated = Assert.Single(await RowsAsync(AuditEventType.UserReactivated, targetId));
        Assert.Equal($"{{\"actor\":\"{adminId}\"}}", reactivated.Detail);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(admin, "POST", Admin + "/users/" + Guid.NewGuid() + "/deactivate", null)).StatusCode);
    }

    [Fact]
    public async Task Admin_MFA_reset_ends_every_session_and_is_audited_as_reset_with_the_actor()
    {
        (Guid adminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid targetId, string targetEmail) = await SeedUserAsync([AuthRoles.User]);
        using Browser admin = await SignedInAsync(adminEmail);
        Assert.Equal(HttpStatusCode.Conflict, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/mfa/reset", null)).StatusCode);

        // Signed in before MFA was on; the factor is planted directly (the reset never reads it).
        using Browser target = await SignedInAsync(targetEmail);
        await UpdateUserAsync(targetId, u =>
        {
            u.MfaEnabled = true;
            u.MfaSecretEncrypted = [1, 2, 3, 4];
        });
        Guid stamp = (await LoadUserAsync(targetId)).SecurityStamp;

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/mfa/reset", null)).StatusCode);

        User after = await LoadUserAsync(targetId);
        Assert.False(after.MfaEnabled);
        Assert.Null(after.MfaSecretEncrypted);
        Assert.NotEqual(stamp, after.SecurityStamp);
        Assert.Equal(HttpStatusCode.Unauthorized, (await target.GetAsync(Me)).StatusCode);
        AuditLog reset = Assert.Single(await RowsAsync(AuditEventType.MfaDisabled, targetId));
        Assert.Equal($"{{\"action\":\"reset\",\"actor\":\"{adminId}\"}}", reset.Detail);

        // Not only the new stamp: every refresh family is revoked and single logout is published for the user.
        List<RefreshToken> tokens = await RefreshTokensAsync(targetId);
        Assert.NotEmpty(tokens);
        Assert.All(tokens, t => Assert.NotNull(t.RevokedUtc));
        Assert.Contains(ended.Seen, e => e.UserId == targetId && e.Scope == SessionEndScope.All && e.Cause == SessionEndCause.MfaReset);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(admin, "POST", Admin + "/users/" + Guid.NewGuid() + "/mfa/reset", null)).StatusCode);
    }

    [Fact]
    public async Task Client_applications_are_managed_through_the_registry_with_audit_and_CORS_invalidation()
    {
        (Guid adminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        using Browser admin = await SignedInAsync(adminEmail);
        string suffix = Guid.NewGuid().ToString("N")[..10];
        string origin = "https://admin-" + suffix + ".example.test";
        ClientApplicationRequest request = new("admin-" + suffix, "Admin app", "api://admin-" + suffix, [origin], [origin + "/callback"], []);

        HttpResponseMessage created = await SendAsync(admin, "POST", Admin + "/apps", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using JsonDocument body = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        Guid appId = body.RootElement.GetProperty("id").GetGuid();
        Assert.Equal("/api/v1/admin/apps/" + appId, created.Headers.Location?.OriginalString);
        Assert.Equal(origin, Cors(await ProbeCorsAsync(origin)));

        HttpResponseMessage invalid = await SendAsync(admin, "POST", Admin + "/apps", request with { ClientId = "x", Audience = "http://plain" });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        string problem = await invalid.Content.ReadAsStringAsync();
        Assert.Contains("clientId", problem, StringComparison.Ordinal);
        Assert.DoesNotContain("http://plain", problem, StringComparison.Ordinal);

        // An update that moves the origin takes effect at once: the old origin loses CORS, the new one gains it.
        string moved = "https://moved-" + suffix + ".example.test";
        ClientApplicationRequest update = request with { Name = "Renamed", AllowedOrigins = [moved], RedirectUris = [moved + "/callback"] };
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(admin, "PUT", Admin + "/apps/" + appId, update)).StatusCode);
        Assert.Equal(string.Empty, Cors(await ProbeCorsAsync(origin)));
        Assert.Equal(moved, Cors(await ProbeCorsAsync(moved)));
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/apps/" + appId + "/deactivate", null)).StatusCode);
        Assert.Equal(string.Empty, Cors(await ProbeCorsAsync(moved)));
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/apps/" + appId + "/activate", null)).StatusCode);
        Assert.Equal(moved, Cors(await ProbeCorsAsync(moved)));
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(admin, "PUT", Admin + "/apps/" + Guid.NewGuid(), request)).StatusCode);

        List<AuditLog> rows = await AppRowsAsync(appId);
        Assert.Equal($"{{\"app\":\"{appId}\",\"source\":\"registry\",\"actor\":\"{adminId}\"}}", Assert.Single(rows, r => r.EventType == nameof(AuditEventType.AppCreated)).Detail);
        Assert.Equal($"{{\"app\":\"{appId}\",\"revoked\":0,\"actor\":\"{adminId}\"}}", Assert.Single(rows, r => r.EventType == nameof(AuditEventType.AppDeactivated)).Detail);
        Assert.Equal(2, rows.Count(r => r.EventType == nameof(AuditEventType.AppUpdated) && r.Detail!.EndsWith($"\"actor\":\"{adminId}\"}}", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task The_last_active_administrator_cannot_be_demoted_or_deactivated()
    {
        (Guid soleId, _) = await SeedUserAsync([AuthRoles.Admin]);
        Guid adminRole = await RoleIdAsync(AuthRoles.Admin);
        await using AdminIsolation isolation = await IsolateAdminsAsync(soleId);

        // Over HTTP the actor must be an administrator too (privilege ceiling), so it always counts; the sole
        // administrator can only be targeted by a host caller (null actor) or by a concurrent change (next tests).
        Assert.Equal(RoleChangeOutcome.LastAdministrator, await InScopeAsync<IRoleAssignmentService, RoleChangeOutcome>(s => s.RemoveUserRoleAsync(soleId, adminRole, AuditContext.None, CancellationToken.None)));
        Assert.Equal(AdminOutcome.LastAdministrator, await InScopeAsync<IUserAdministrationService, AdminOutcome>(s => s.DeactivateAsync(soleId, AuditContext.None, CancellationToken.None)));
        Assert.True((await LoadUserAsync(soleId)).IsActive);
        Assert.True(await HasRoleAsync(soleId, adminRole));
    }

    [Fact]
    public async Task Removing_the_Admin_role_from_a_stale_account_is_not_refused_as_the_last_administrator()
    {
        (Guid staleId, _) = await SeedUserAsync([AuthRoles.Admin]);
        Guid adminRole = await RoleIdAsync(AuthRoles.Admin);
        await using AdminIsolation isolation = await IsolateAdminsAsync(staleId);
        await UpdateUserAsync(staleId, u => u.IsActive = false);

        // The stale account is not an active administrator, so removing its role does not lower the count.
        Assert.Equal(RoleChangeOutcome.Changed, await InScopeAsync<IRoleAssignmentService, RoleChangeOutcome>(s => s.RemoveUserRoleAsync(staleId, adminRole, AuditContext.None, CancellationToken.None)));
        Assert.False(await HasRoleAsync(staleId, adminRole));
    }

    [Fact]
    public async Task Two_administrators_demoting_each_other_at_once_leave_one_administrator()
    {
        (Guid firstId, string firstEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid secondId, string secondEmail) = await SeedUserAsync([AuthRoles.Admin]);
        Guid adminRole = await RoleIdAsync(AuthRoles.Admin);
        using Browser first = await SignedInAsync(firstEmail);
        using Browser second = await SignedInAsync(secondEmail);
        await using AdminIsolation isolation = await IsolateAdminsAsync(firstId, secondId);

        HttpResponseMessage[] answers = await Task.WhenAll(
            SendAsync(first, "DELETE", Admin + "/users/" + secondId + "/roles/" + adminRole, null),
            SendAsync(second, "DELETE", Admin + "/users/" + firstId + "/roles/" + adminRole, null));

        // The loser is refused whichever way the race goes: last administrator (409), no longer an administrator (403),
        // or its session already ended (401).
        Assert.Single(answers, a => a.StatusCode == HttpStatusCode.NoContent);
        Assert.Single(answers, a => a.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized);
        Assert.Equal(1, (await HasRoleAsync(firstId, adminRole) ? 1 : 0) + (await HasRoleAsync(secondId, adminRole) ? 1 : 0));
    }

    [Fact]
    public async Task Two_administrators_deactivating_each_other_at_once_leave_one_active_administrator()
    {
        (Guid firstId, string firstEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid secondId, string secondEmail) = await SeedUserAsync([AuthRoles.Admin]);
        using Browser first = await SignedInAsync(firstEmail);
        using Browser second = await SignedInAsync(secondEmail);
        await using AdminIsolation isolation = await IsolateAdminsAsync(firstId, secondId);

        HttpResponseMessage[] answers = await Task.WhenAll(
            SendAsync(first, "POST", Admin + "/users/" + secondId + "/deactivate", null),
            SendAsync(second, "POST", Admin + "/users/" + firstId + "/deactivate", null));

        Assert.Single(answers, a => a.StatusCode == HttpStatusCode.NoContent);
        Assert.Single(answers, a => a.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.Unauthorized);
        Assert.Equal(1, ((await LoadUserAsync(firstId)).IsActive ? 1 : 0) + ((await LoadUserAsync(secondId)).IsActive ? 1 : 0));
    }

    [Fact]
    public async Task A_role_manager_who_is_not_an_administrator_can_only_give_rights_they_hold()
    {
        string managerRoleName = "Manager-" + Guid.NewGuid().ToString("N")[..8];
        Guid managerRole = await CreateRoleAsync(managerRoleName, [AuthPermissions.RolesManage]);
        (Guid managerId, string managerEmail) = await SeedUserAsync([managerRoleName]);
        (Guid targetId, _) = await SeedUserAsync([AuthRoles.User]);
        (Guid otherAdminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        Guid adminRole = await RoleIdAsync(AuthRoles.Admin);
        Guid writerRole = await RoleIdAsync(RoleFor(AuthPermissions.UsersWrite));
        Guid otherRole = await CreateRoleAsync("Other-" + Guid.NewGuid().ToString("N")[..8], []);
        Guid usersWrite = await PermissionIdAsync(AuthPermissions.UsersWrite);
        Guid rolesManage = await PermissionIdAsync(AuthPermissions.RolesManage);
        using Browser manager = await SignedInAsync(managerEmail);

        foreach ((string method, string path, object? body) in new (string, string, object?)[]
        {
            ("POST", Admin + "/users/" + managerId + "/roles", new AdminRoleAssignmentRequest(adminRole)),
            ("POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(adminRole)),
            ("POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(writerRole)),
            ("POST", Admin + "/roles/" + managerRole + "/permissions", new AdminPermissionGrantRequest(usersWrite)),
            ("POST", Admin + "/roles/" + otherRole + "/permissions", new AdminPermissionGrantRequest(usersWrite)),
            ("DELETE", Admin + "/users/" + otherAdminId + "/roles/" + adminRole, null),
        })
        {
            HttpResponseMessage response = await SendAsync(manager, method, path, body);
            Assert.True(response.StatusCode == HttpStatusCode.Forbidden, method + " " + path + " answered " + (int)response.StatusCode);
        }

        Assert.False(await HasRoleAsync(managerId, adminRole));
        Assert.False(await HasRoleAsync(targetId, adminRole));
        Assert.False(await HasRoleAsync(targetId, writerRole));
        Assert.False(await RoleHasPermissionAsync(managerRole, usersWrite));
        Assert.False(await RoleHasPermissionAsync(otherRole, usersWrite));
        Assert.True(await HasRoleAsync(otherAdminId, adminRole));
        Assert.Empty(await RowsAsync(AuditEventType.RoleAssigned, targetId));

        // What the manager holds, they may pass on.
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(manager, "POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(managerRole))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(manager, "POST", Admin + "/roles/" + otherRole + "/permissions", new AdminPermissionGrantRequest(rolesManage))).StatusCode);
        Assert.True(await HasRoleAsync(targetId, managerRole));

        // An administrator has no ceiling.
        using Browser admin = await SignedInAsync(adminEmail);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/roles", new AdminRoleAssignmentRequest(writerRole))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/roles/" + otherRole + "/permissions", new AdminPermissionGrantRequest(usersWrite))).StatusCode);
    }

    [Fact]
    public async Task A_user_writer_who_is_not_an_administrator_cannot_change_an_administrators_account()
    {
        (Guid adminId, _) = await SeedUserAsync([AuthRoles.Admin]);
        await UpdateUserAsync(adminId, u =>
        {
            u.MfaEnabled = true;
            u.MfaSecretEncrypted = [1, 2, 3, 4];
        });
        (Guid plainId, _) = await SeedUserAsync([AuthRoles.User]);
        (_, string writerEmail) = await SeedUserAsync([RoleFor(AuthPermissions.UsersWrite)]);
        using Browser writer = await SignedInAsync(writerEmail);

        foreach (string action in new[] { "/deactivate", "/mfa/reset" })
        {
            HttpResponseMessage response = await SendAsync(writer, "POST", Admin + "/users/" + adminId + action, null);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Contains("Only an administrator can change an administrator's account.", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        User untouched = await LoadUserAsync(adminId);
        Assert.True(untouched.IsActive);
        Assert.True(untouched.MfaEnabled);
        Assert.Empty(await RowsAsync(AuditEventType.UserDeactivated, adminId));

        await UpdateUserAsync(adminId, u => u.IsActive = false);
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(writer, "POST", Admin + "/users/" + adminId + "/reactivate", null)).StatusCode);
        Assert.False((await LoadUserAsync(adminId)).IsActive);

        // Other accounts are fine.
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(writer, "POST", Admin + "/users/" + plainId + "/deactivate", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(writer, "POST", Admin + "/users/" + plainId + "/reactivate", null)).StatusCode);
    }

    [Fact]
    public async Task Reactivation_clears_the_lockout()
    {
        (_, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid targetId, string targetEmail) = await SeedUserAsync([AuthRoles.User]);
        using Browser admin = await SignedInAsync(adminEmail);
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/deactivate", null)).StatusCode);
        await UpdateUserAsync(targetId, u =>
        {
            u.FailedLoginCount = 7;
            u.LockoutEndUtc = DateTime.UtcNow.AddHours(1);
            u.LockoutLevel = 3;
        });

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(admin, "POST", Admin + "/users/" + targetId + "/reactivate", null)).StatusCode);

        User after = await LoadUserAsync(targetId);
        Assert.Equal((0, null, 0), (after.FailedLoginCount, after.LockoutEndUtc, after.LockoutLevel));
        Assert.Equal(HttpStatusCode.OK, (await TrySignInAsync(targetEmail)).StatusCode);
    }

    [Fact]
    public async Task Administrators_cannot_lock_themselves_out_or_strip_the_Admin_role()
    {
        (Guid adminId, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        Guid adminRole = await RoleIdAsync(AuthRoles.Admin);
        Guid customRole = await CreateRoleAsync("Self-" + Guid.NewGuid().ToString("N")[..8], [AuthPermissions.AuditRead]);
        await AddRoleAsync(adminId, customRole);
        Guid auditRead = await PermissionIdAsync(AuthPermissions.AuditRead);
        using Browser admin = await SignedInAsync(adminEmail);

        foreach ((string method, string path) in new[]
        {
            ("POST", Admin + "/users/" + adminId + "/deactivate"),
            ("POST", Admin + "/users/" + adminId + "/mfa/reset"),
            ("DELETE", Admin + "/users/" + adminId + "/roles/" + adminRole),
            ("DELETE", Admin + "/users/" + adminId + "/roles/" + customRole),
            ("DELETE", Admin + "/roles/" + customRole + "/permissions/" + auditRead),
            ("DELETE", Admin + "/roles/" + adminRole + "/permissions/" + auditRead),
        })
        {
            HttpResponseMessage response = await SendAsync(admin, method, path, null);
            Assert.True(response.StatusCode == HttpStatusCode.Conflict, method + " " + path + " answered " + (int)response.StatusCode);
        }

        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync(Me)).StatusCode);
        Assert.True(await HasRoleAsync(adminId, adminRole));
        Assert.True(await HasRoleAsync(adminId, customRole));
        Assert.Empty(await RowsAsync(AuditEventType.RoleRemoved, adminId));
    }

    [Fact]
    public async Task Reads_return_no_secrets_and_lists_are_capped()
    {
        (_, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid targetId, _) = await SeedUserAsync([AuthRoles.User], email: "listed-" + Guid.NewGuid().ToString("N")[..8] + "@example.test");
        await UpdateUserAsync(targetId, u => u.MfaSecretEncrypted = [9, 9, 9]);
        User stored = await LoadUserAsync(targetId);
        using Browser admin = await SignedInAsync(adminEmail);

        HttpResponseMessage detail = await admin.GetAsync(Admin + "/users/" + targetId);
        string detailBody = await detail.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.Equal("no-store", detail.Headers.CacheControl?.ToString());
        Assert.Contains("\"User\"", detailBody.Replace("\"user\"", "\"User\"", StringComparison.Ordinal), StringComparison.Ordinal);
        foreach (string secret in new[] { stored.PasswordHash, stored.SecurityStamp.ToString(), Convert.ToBase64String(stored.MfaSecretEncrypted!), "passwordHash", "securityStamp", "mfaSecret", "rowVersion" })
        {
            Assert.DoesNotContain(secret, detailBody, StringComparison.OrdinalIgnoreCase);
        }

        HttpResponseMessage page = await admin.GetAsync(Admin + "/users?email=" + Uri.EscapeDataString(stored.Email[..12]) + "&pageSize=5");
        using JsonDocument list = JsonDocument.Parse(await page.Content.ReadAsStringAsync());
        Assert.Equal(1, list.RootElement.GetProperty("total").GetInt32());
        Assert.Equal(targetId, list.RootElement.GetProperty("items")[0].GetProperty("id").GetGuid());

        foreach (string query in new[] { "/users?pageSize=101", "/users?pageSize=0", "/users?page=0", "/audit?limit=201", "/audit?limit=0", "/audit?eventType=Nope", "/audit?before=0", "/users?email=" + new string('a', 257) })
        {
            Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync(Admin + query)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync(Admin + "/users/" + Guid.NewGuid())).StatusCode);
    }

    [Fact]
    public async Task Audit_rows_and_their_reasons_are_shown_only_to_audit_readers()
    {
        (Guid targetId, string targetEmail) = await SeedUserAsync([AuthRoles.User]);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TrySignInAsync(targetEmail, "wrong-password-123")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TrySignInAsync(targetEmail, "wrong-password-456")).StatusCode);
        (_, string readerEmail) = await SeedUserAsync([RoleFor(AuthPermissions.UsersRead)]);
        (_, string auditorEmail) = await SeedUserAsync([RoleFor(AuthPermissions.AuditRead)]);

        using Browser reader = await SignedInAsync(readerEmail);
        string asReader = await (await reader.GetAsync(Admin + "/users/" + targetId)).Content.ReadAsStringAsync();
        Assert.DoesNotContain("wrong_password", asReader, StringComparison.Ordinal);
        Assert.DoesNotContain("reason", asReader, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync(Admin + "/audit?userId=" + targetId)).StatusCode);

        using Browser auditor = await SignedInAsync(auditorEmail);
        HttpResponseMessage first = await auditor.GetAsync(Admin + "/audit?userId=" + targetId + "&eventType=LoginFailed&limit=1");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using JsonDocument page = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        JsonElement row = Assert.Single(page.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("LoginFailed", row.GetProperty("eventType").GetString());
        Assert.Equal("wrong_password", row.GetProperty("detail").GetProperty("reason").GetString());
        long next = page.RootElement.GetProperty("nextBefore").GetInt64();

        using JsonDocument second = JsonDocument.Parse(await (await auditor.GetAsync(Admin + "/audit?userId=" + targetId + "&eventType=LoginFailed&limit=1&before=" + next)).Content.ReadAsStringAsync());
        Assert.Single(second.RootElement.GetProperty("items").EnumerateArray());
        Assert.True(second.RootElement.GetProperty("items")[0].GetProperty("id").GetInt64() < next);
        using JsonDocument third = JsonDocument.Parse(await (await auditor.GetAsync(Admin + "/audit?userId=" + targetId + "&eventType=LoginFailed&limit=5")).Content.ReadAsStringAsync());
        Assert.Equal(2, third.RootElement.GetProperty("items").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, third.RootElement.GetProperty("nextBefore").ValueKind);
    }

    [Fact]
    public async Task State_changes_need_the_antiforgery_token_and_a_JSON_body()
    {
        (_, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        (Guid targetId, _) = await SeedUserAsync([AuthRoles.User]);
        Guid auditorRole = await RoleIdAsync(RoleFor(AuthPermissions.AuditRead));
        using Browser admin = await SignedInAsync(adminEmail);

        HttpResponseMessage noToken = await admin.SendAsync(HttpMethod.Post, Admin + "/users/" + targetId + "/deactivate", sendXsrf: false);
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
        Assert.Contains("Missing or invalid antiforgery token.", await noToken.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.SendAsync(HttpMethod.Post, Admin + "/users/" + targetId + "/deactivate", originOverride: "https://evil.example")).StatusCode);

        HttpResponseMessage text = await admin.SendAsync(HttpMethod.Post, Admin + "/users/" + targetId + "/roles", configure: r =>
            r.Content = new StringContent("{\"roleId\":\"" + auditorRole + "\"}", Encoding.UTF8, "text/plain"));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, text.StatusCode);

        HttpResponseMessage huge = await admin.SendAsync(HttpMethod.Put, Admin + "/apps/" + Guid.NewGuid(), configure: r =>
            r.Content = new StringContent("{\"name\":\"" + new string('a', 20_000) + "\"}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, huge.StatusCode);

        Assert.True((await LoadUserAsync(targetId)).IsActive);
        Assert.False(await HasRoleAsync(targetId, auditorRole));
    }

    [Fact]
    public async Task The_admin_API_has_its_own_rate_limit()
    {
        await using WebApplicationFactory<Program> limited = WithSettings(new Dictionary<string, string?>
        {
            ["RateLimiting:Policies:Admin:PerIp:PermitLimit"] = "3",
        });
        (_, string adminEmail) = await SeedUserAsync([AuthRoles.Admin]);
        using Browser admin = await SignedInAsync(adminEmail, limited);

        HttpStatusCode[] codes = new HttpStatusCode[4];
        for (int i = 0; i < codes.Length; i++)
        {
            codes[i] = (await admin.GetAsync(Admin + "/roles")).StatusCode;
        }

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], codes);
    }

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> extra)
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "100000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "100000",
            ["RateLimiting:Policies:Refresh:PerIp:PermitLimit"] = "100000",
            ["RateLimiting:Policies:Admin:PerIp:PermitLimit"] = "100000",
        };
        foreach (KeyValuePair<string, string?> setting in extra)
        {
            settings[setting.Key] = setting.Value;
        }

        return api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
            builder.ConfigureTestServices(services => services.AddSingleton<ISessionEndedListener>(ended));
        });
    }

    private static string RoleFor(string permission) => "Only-" + permission;

    private static string Cors(HttpResponseMessage response) => response.Header("Access-Control-Allow-Origin");

    private async Task<HttpResponseMessage> ProbeCorsAsync(string origin)
    {
        using HttpClient client = api.CreateHttpsClient(app);
        using HttpRequestMessage request = new(HttpMethod.Get, TestEndpoints.Prefix + "/ping");
        request.Headers.TryAddWithoutValidation("Origin", origin);
        return await client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> SendAsync(Browser browser, string method, string path, object? body) =>
        method == "GET"
            ? browser.GetAsync(path)
            : browser.SendAsync(new HttpMethod(method), path, configure: body is null ? null : r =>
                r.Content = new StringContent(JsonSerializer.Serialize(body, Web), Encoding.UTF8, "application/json"));

    private Task<Browser> SignedInAsync(string email) => SignedInAsync(email, app);

    private static async Task<Browser> SignedInAsync(string email, WebApplicationFactory<Program> factory)
    {
        Browser browser = new(factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage login = await browser.SendAsync(HttpMethod.Post, Login, configure: r =>
            r.Content = new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        await browser.GetAsync(Me);
        return browser;
    }

    private async Task<HttpResponseMessage> TrySignInAsync(string email, string password = Password)
    {
        using Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return await browser.SendAsync(HttpMethod.Post, Login, configure: r =>
            r.Content = new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = password }), Encoding.UTF8, "application/json"));
    }

    /// <summary>
    /// Makes the given accounts the only active Admin holders for the test (the shared database has others), and restores
    /// the others afterwards. Tests in this collection run one at a time.
    /// </summary>
    private async Task<AdminIsolation> IsolateAdminsAsync(params Guid[] keep)
    {
        Guid adminRole = await RoleIdAsync(AuthRoles.Admin);
        List<Guid> parked = await QueryAsync(async context =>
        {
            List<User> others = await context.User
                .Where(u => u.IsActive && u.UserRoles.Any(ur => ur.RoleId == adminRole) && !keep.Contains(u.Id))
                .ToListAsync();
            foreach (User user in others)
            {
                user.IsActive = false;
            }

            await context.SaveChangesAsync();
            return others.Select(u => u.Id).ToList();
        });
        return new AdminIsolation(this, parked);
    }

    private sealed class AdminIsolation(AdminApiTests owner, List<Guid> parked) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync() => await owner.QueryAsync(context =>
            context.User.Where(u => parked.Contains(u.Id)).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, true)));
    }

    private async Task EnsurePermissionRolesAsync()
    {
        foreach (string permission in AuthPermissions.All)
        {
            string normalized = RoleFor(permission).ToUpperInvariant();
            if (!await QueryAsync(context => context.Role.AnyAsync(r => r.ClientApplicationId == null && r.NormalizedName == normalized)))
            {
                await CreateRoleAsync(RoleFor(permission), [permission]);
            }
        }
    }

    private Task<Guid> CreateRoleAsync(string name, string[] permissions) => QueryAsync(async context =>
    {
        Role role = new() { Name = name, NormalizedName = name.ToUpperInvariant() };
        context.Role.Add(role);
        foreach (string code in permissions)
        {
            Permission permission = await context.Permission.SingleAsync(p => p.Code == code);
            context.RolePermission.Add(new RolePermission { Role = role, PermissionId = permission.Id });
        }

        await context.SaveChangesAsync();
        return role.Id;
    });

    private Task<Guid> RoleIdAsync(string name)
    {
        string normalized = name.ToUpperInvariant();
        return QueryAsync(context => context.Role.Where(r => r.ClientApplicationId == null && r.NormalizedName == normalized).Select(r => r.Id).SingleAsync());
    }

    private Task<Guid> PermissionIdAsync(string code) =>
        QueryAsync(context => context.Permission.Where(p => p.Code == code).Select(p => p.Id).SingleAsync());

    private Task<int> AddRoleAsync(Guid userId, Guid roleId) => QueryAsync(context =>
    {
        context.UserRole.Add(new UserRole { UserId = userId, RoleId = roleId, AssignedUtc = DateTime.UtcNow });
        return context.SaveChangesAsync();
    });

    private Task<bool> RoleHasPermissionAsync(Guid roleId, Guid permissionId) =>
        QueryAsync(context => context.RolePermission.AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId));

    private Task<List<RefreshToken>> RefreshTokensAsync(Guid userId) =>
        QueryAsync(context => context.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync());

    private async Task<T> InScopeAsync<TService, T>(Func<TService, Task<T>> action)
        where TService : notnull
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    private Task<bool> HasRoleAsync(Guid userId, Guid roleId) =>
        QueryAsync(context => context.UserRole.AnyAsync(ur => ur.UserId == userId && ur.RoleId == roleId));

    private Task<int> UpdateUserAsync(Guid userId, Action<User> change) => QueryAsync(async context =>
    {
        User user = await context.User.SingleAsync(u => u.Id == userId);
        change(user);
        return await context.SaveChangesAsync();
    });

    private Task<User> LoadUserAsync(Guid userId) => QueryAsync(context => context.User.AsNoTracking().SingleAsync(u => u.Id == userId));

    private Task<List<AuditLog>> RowsAsync(AuditEventType type, Guid? userId)
    {
        string name = type.ToString();
        return QueryAsync(context => context.AuditLog.AsNoTracking()
            .Where(a => a.EventType == name && (userId == null || a.UserId == userId))
            .OrderBy(a => a.Id)
            .ToListAsync());
    }

    private Task<List<AuditLog>> AppRowsAsync(Guid appId)
    {
        string id = appId.ToString("D");
        return QueryAsync(context => context.AuditLog.AsNoTracking().Where(a => a.Detail != null && a.Detail.Contains(id)).OrderBy(a => a.Id).ToListAsync());
    }

    private async Task<(Guid Id, string Email)> SeedUserAsync(string[] roleNames, string? email = null)
    {
        email ??= "admin-api-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        User user = new()
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = true,
            PasswordHash = hash,
            DisplayName = "Admin Api Tester",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        };
        context.User.Add(user);
        foreach (string name in roleNames)
        {
            string normalized = name.ToUpperInvariant();
            Role role = await context.Role.SingleAsync(r => r.ClientApplicationId == null && r.NormalizedName == normalized);
            context.UserRole.Add(new UserRole { User = user, RoleId = role.Id, AssignedUtc = now });
        }

        await context.SaveChangesAsync();
        return (user.Id, email);
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    /// <summary>Records every single-logout event the host publishes.</summary>
    private sealed class RecordingListener : ISessionEndedListener
    {
        public System.Collections.Concurrent.ConcurrentBag<SessionEnded> Seen { get; } = [];

        public Task OnSessionEndedAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken)
        {
            Seen.Add(ended);
            return Task.CompletedTask;
        }
    }
}
