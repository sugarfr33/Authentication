using System.Net;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.ClientApplications;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Auth.IntegrationTests.Api;

/// <summary>T18 through the real host: app token claims, audience isolation from this API, and CORS from the registry.</summary>
[Collection(ApiTestGroup.Name)]
public sealed class ClientApplicationApiTests(ApiFixture api)
{
    [Fact]
    public async Task An_app_token_carries_the_app_audience_client_id_session_and_app_roles_but_never_unlocks_this_API()
    {
        ClientApplicationResponse app = await CreateAppAsync(active: true);
        Guid userId = await SeedUserWithAppAdminRoleAsync(app.Id);

        SignedIn session;
        await using (AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope())
        {
            session = (await scope.ServiceProvider.GetRequiredService<IClientSessionService>()
                .StartAsync(userId, app.ClientId, Guid.NewGuid(), new RefreshContext("203.0.113.9", "tests"), AuditContext.None, CancellationToken.None)).Value!;
        }

        JsonWebToken token = new(session.AccessToken.Jwt);
        Assert.Equal([app.Audience], token.Audiences);
        Assert.Equal(app.ClientId, token.GetClaim(AuthClaimTypes.ClientId).Value);
        Assert.Equal(session.RefreshToken.FamilyId.ToString(), token.GetClaim(AuthClaimTypes.SessionId).Value);
        Assert.Contains(token.Claims, c => c.Type == AuthClaimTypes.Role && c.Value == "app:" + app.ClientId + ":" + AuthRoles.Admin);
        Assert.DoesNotContain(token.Claims, c => c.Type == AuthClaimTypes.Role && c.Value == AuthRoles.Admin);
        Assert.Contains(token.Claims, c => c.Type == AuthClaimTypes.Permission && c.Value == AuthPermissions.UsersWrite);
        Assert.Equal(app.Id, session.RefreshToken.ClientApplicationId);

        // T16 audit note: an application role named Admin must never satisfy role:Admin on this API (audience-strict).
        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        browser.Plant(AuthCookieNames.Access, session.AccessToken.Jwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync(TestEndpoints.Prefix + "/policy/" + AuthPolicies.AdminRole)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync(TestEndpoints.Prefix + "/policy/" + AuthPermissions.UsersWrite)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    /// <summary>Defence in depth: a server-signed token with this API's audience but a client_id is still refused.</summary>
    [Fact]
    public async Task A_token_with_a_client_id_is_never_a_browser_session_of_this_API()
    {
        AccessToken forged;
        await using (AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope())
        {
            ITokenService tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
            IRefreshTokenService refresh = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
            IssuedRefreshToken family = await refresh.IssueAsync(ApiFixture.UserId, null, new RefreshContext("203.0.113.9", "tests"), CancellationToken.None);
            forged = await tokens.CreateAccessTokenAsync(
                new AccessTokenRequest(ApiFixture.UserId, "api.user@example.test", "Api User", [AuthRoles.Admin], [AuthPermissions.UsersWrite], ApiFixture.Issuer, "some-app", family.FamilyId),
                CancellationToken.None);
        }

        using Browser browser = new(api.Factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        browser.Plant(AuthCookieNames.Access, forged.Jwt);

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync(TestEndpoints.Prefix + "/policy/" + AuthPolicies.AdminRole)).StatusCode);
    }

    [Fact]
    public async Task CORS_allows_exactly_the_registered_active_origins_and_drops_a_deactivated_app_at_once()
    {
        ClientApplicationResponse app = await CreateAppAsync(active: true);
        string origin = app.AllowedOrigins[0];
        using HttpClient client = api.CreateHttpsClient();

        string allowed = (await SimpleGetAsync(client, origin)).Header("Access-Control-Allow-Origin");
        string lookalike = (await SimpleGetAsync(client, origin + ".evil.example")).Header("Access-Control-Allow-Origin");
        await using (AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().DeactivateAsync(app.Id, AuditContext.None, CancellationToken.None));
        }

        string afterDeactivation = (await SimpleGetAsync(client, origin)).Header("Access-Control-Allow-Origin");

        Assert.Equal(origin, allowed);
        Assert.Equal(string.Empty, lookalike);
        Assert.Equal(string.Empty, afterDeactivation);
    }

    private async Task<ClientApplicationResponse> CreateAppAsync(bool active)
    {
        string id = "api-app-" + Guid.NewGuid().ToString("N")[..10];
        await using AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope();
        ClientApplicationResult result = await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().CreateAsync(
            new ClientApplicationRequest(id, "Api test " + id, "api://" + id, ["https://" + id + ".example.com"], ["https://" + id + ".example.com/cb"], []),
            active,
            AuditContext.None,
            CancellationToken.None);
        return result.Application!;
    }

    /// <summary>A verified user with the global User role and an Admin role scoped to the application (all permissions).</summary>
    private async Task<Guid> SeedUserWithAppAdminRoleAsync(Guid applicationId)
    {
        await using AsyncServiceScope scope = api.Factory.Services.CreateAsyncScope();
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        string email = "appuser-" + Guid.NewGuid().ToString("N")[..10] + "@example.test";
        User user = new()
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = true,
            PasswordHash = string.Empty,
            DisplayName = "App User",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        };
        context.User.Add(user);
        Role appAdmin = new() { Name = AuthRoles.Admin, NormalizedName = AuthRoles.Admin.ToUpperInvariant(), ClientApplicationId = applicationId };
        context.Role.Add(appAdmin);
        foreach (Permission permission in await context.Permission.ToListAsync())
        {
            context.RolePermission.Add(new RolePermission { Role = appAdmin, PermissionId = permission.Id });
        }

        context.UserRole.Add(new UserRole { User = user, Role = appAdmin, AssignedUtc = now });
        await context.SaveChangesAsync();
        return user.Id;
    }

    private static async Task<HttpResponseMessage> SimpleGetAsync(HttpClient client, string origin)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, TestEndpoints.Prefix + "/ping");
        request.Headers.TryAddWithoutValidation("Origin", origin);
        return await client.SendAsync(request);
    }
}
