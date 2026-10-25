using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Api;

/// <summary>T16: permission and role policies through the real pipeline, token claims, and role changes at the next mint.</summary>
[Collection(ApiTestGroup.Name)]
public sealed class AuthorizationApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Login = "/api/v1/auth/login";
    private const string Password = "violet-canyon-7319";
    private const string AuditorRole = "Auditor";

    private WebApplicationFactory<Program> app = null!;

    public async Task InitializeAsync()
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Refresh:PerIp:PermitLimit"] = "1000",
        };
        app = api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        });
        await EnsureAuditorRoleAsync();
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    public static TheoryData<string, string> Matrix()
    {
        TheoryData<string, string> data = [];
        foreach (string holder in new[] { "none", AuthRoles.User, AuthRoles.Admin, AuditorRole })
        {
            foreach (string policy in TestEndpoints.PolicyNames)
            {
                data.Add(holder, policy);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task Policies_allow_exactly_the_holders_of_the_permission_or_role(string holder, string policy)
    {
        string email = await SeedUserAsync(holder == "none" ? [] : [holder]);
        using Browser browser = await SignedInAsync(email);

        HttpResponseMessage response = await browser.GetAsync(TestEndpoints.Prefix + "/policy/" + policy);

        bool allowed = holder == AuthRoles.Admin || (holder == AuditorRole && policy == AuthPermissions.AuditRead);
        Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.Forbidden, response.StatusCode);
        if (!allowed)
        {
            string body = await response.Content.ReadAsStringAsync();
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            Assert.Contains("Access denied.", body, StringComparison.Ordinal);
            Assert.DoesNotContain(policy, body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Without_a_session_every_policy_answers_401()
    {
        using Browser browser = new(app);

        foreach (string policy in TestEndpoints.PolicyNames)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync(TestEndpoints.Prefix + "/policy/" + policy)).StatusCode);
        }
    }

    /// <summary>Audit MEDIUM-1: default deny. Every product endpoint states its access rule; the public ones are exactly these.</summary>
    [Fact]
    public void Every_endpoint_requires_authorization_unless_it_is_explicitly_anonymous()
    {
        string[] expectedAnonymous =
        [
            "/.well-known/jwks.json",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/login",
            "/api/v1/auth/logout",
            "/api/v1/auth/refresh",
            "/api/v1/auth/register",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/verify-email",
            "/api/v1/oauth/authorize",
            "/api/v1/oauth/logout",
            "/api/v1/oauth/token",
            "/health",
            "/health/ready",
        ];
        List<RouteEndpoint> product = [.. app.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => !(e.RoutePattern.RawText ?? string.Empty).StartsWith(TestEndpoints.Prefix, StringComparison.Ordinal))];

        Assert.NotEmpty(product);
        Assert.All(product, e => Assert.True(
            e.Metadata.GetMetadata<IAllowAnonymous>() is not null || e.Metadata.GetOrderedMetadata<IAuthorizeData>().Count > 0,
            e.RoutePattern.RawText + " has neither RequireAuthorization nor AllowAnonymous"));
        Assert.Equal(
            expectedAnonymous,
            product.Where(e => e.Metadata.GetMetadata<IAllowAnonymous>() is not null).Select(e => e.RoutePattern.RawText!).Distinct().Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task An_api_endpoint_that_states_no_rule_is_closed_by_default()
    {
        using Browser anonymous = new(app);
        using Browser signedIn = await SignedInAsync(await SeedUserAsync([]));

        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(TestEndpoints.Prefix + "/unmarked")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await signedIn.GetAsync(TestEndpoints.Prefix + "/unmarked")).StatusCode);
    }

    [Fact]
    public async Task The_access_token_carries_user_session_roles_permissions_and_the_default_audience()
    {
        string email = await SeedUserAsync([AuthRoles.Admin, AuthRoles.User]);
        using Browser browser = await SignedInAsync(email);

        JsonWebToken token = new(browser.CookieValue(AuthCookieNames.Access));

        Assert.Equal((await LoadUserAsync(email)).Id.ToString(), token.Subject);
        Assert.True(Guid.TryParse(token.GetClaim(AuthClaimTypes.SessionId).Value, out _));
        Assert.Equal(ApiFixture.Issuer, token.Issuer);
        Assert.Equal([ApiFixture.Issuer], token.Audiences);
        Assert.Equal([AuthRoles.Admin, AuthRoles.User], token.Claims.Where(c => c.Type == AuthClaimTypes.Role).Select(c => c.Value).Order(StringComparer.Ordinal));
        Assert.Equal(AuthPermissions.All.Order(StringComparer.Ordinal), token.Claims.Where(c => c.Type == AuthClaimTypes.Permission).Select(c => c.Value).Order(StringComparer.Ordinal));
        Assert.Null(token.Claims.FirstOrDefault(c => c.Type == AuthClaimTypes.ClientId));
    }

    /// <summary>
    /// Reviewer note b: the access token travels in a cookie (browsers drop cookies over 4096 bytes). The largest
    /// realistic token today (every role and permission, longest email, display name of escaped non-ASCII characters)
    /// must stay well below that, so the budget is visible before per-application roles add claims.
    /// </summary>
    [Fact]
    public async Task The_largest_realistic_access_token_stays_under_3500_bytes()
    {
        string email = new string('a', 64) + "@" + new string('b', 62) + "." + new string('c', 62) + "." + new string('d', 50) + ".test";
        string name = new((char)0xE9, 128);
        await SeedUserAsync([AuthRoles.Admin, AuthRoles.User, AuditorRole], email, name);
        using Browser browser = await SignedInAsync(email);

        string token = browser.CookieValue(AuthCookieNames.Access);

        Assert.True(email.Length >= 245, "the test email should be near the 256 limit");
        Assert.Equal(name, new JsonWebToken(token).GetClaim(AuthClaimTypes.Name).Value);
        Assert.True(token.Length < 3500, "access token is " + token.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + " bytes");
    }

    [Fact]
    public async Task A_role_removal_takes_effect_at_the_next_token_mint()
    {
        string email = await SeedUserAsync([AuditorRole]);
        using Browser browser = await SignedInAsync(email);
        string audit = TestEndpoints.Prefix + "/policy/" + AuthPermissions.AuditRead;
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(audit)).StatusCode);
        Guid userId = (await LoadUserAsync(email)).Id;

        await QueryAsync(c => c.UserRole.Where(ur => ur.UserId == userId).ExecuteDeleteAsync());
        HttpStatusCode beforeMint = (await browser.GetAsync(audit)).StatusCode;
        HttpStatusCode refresh = (await browser.SendAsync(HttpMethod.Post, "/api/v1/auth/refresh")).StatusCode;
        HttpStatusCode afterMint = (await browser.GetAsync(audit)).StatusCode;

        Assert.Equal(HttpStatusCode.OK, beforeMint);
        Assert.Equal(HttpStatusCode.NoContent, refresh);
        Assert.Equal(HttpStatusCode.Forbidden, afterMint);
    }

    [Fact]
    public async Task Claims_signed_by_anyone_but_the_server_are_never_trusted()
    {
        string email = await SeedUserAsync([]);
        using Browser browser = await SignedInAsync(email);
        JsonWebToken real = new(browser.CookieValue(AuthCookieNames.Access));
        using ECDsa attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SecurityTokenDescriptor forged = new()
        {
            Issuer = ApiFixture.Issuer,
            Audience = ApiFixture.Issuer,
            Expires = DateTime.UtcNow.AddMinutes(10),
            TokenType = "at+jwt",
            Subject = new ClaimsIdentity(
            [
                new Claim(AuthClaimTypes.Subject, real.Subject),
                new Claim(AuthClaimTypes.SessionId, real.GetClaim(AuthClaimTypes.SessionId).Value),
                new Claim(AuthClaimTypes.Role, AuthRoles.Admin),
                new Claim(AuthClaimTypes.Permission, AuthPermissions.UsersWrite),
            ]),
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(attackerKey) { KeyId = ApiFixture.SigningKid }, SecurityAlgorithms.EcdsaSha256),
        };
        browser.Plant(AuthCookieNames.Access, new JsonWebTokenHandler().CreateToken(forged));

        HttpResponseMessage response = await browser.GetAsync(TestEndpoints.Prefix + "/policy/" + AuthPermissions.UsersWrite);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static StringContent Json(Dictionary<string, string> body) => new(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    private async Task<Browser> SignedInAsync(string email)
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage login = await browser.SendAsync(HttpMethod.Post, Login, configure: r =>
            r.Content = Json(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return browser;
    }

    /// <summary>A custom global role holding only audit.read (created once per database).</summary>
    private async Task EnsureAuditorRoleAsync() => await QueryAsync(async context =>
    {
        string normalized = AuditorRole.ToUpperInvariant();
        if (await context.Role.AnyAsync(r => r.ClientApplicationId == null && r.NormalizedName == normalized))
        {
            return 0;
        }

        Permission auditRead = await context.Permission.SingleAsync(p => p.Code == AuthPermissions.AuditRead);
        Role role = new() { Name = AuditorRole, NormalizedName = normalized };
        context.Role.Add(role);
        context.RolePermission.Add(new RolePermission { Role = role, PermissionId = auditRead.Id });
        return await context.SaveChangesAsync();
    });

    private async Task<string> SeedUserAsync(string[] roleNames, string? email = null, string displayName = "Authz Tester")
    {
        email ??= "authz-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
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
            DisplayName = displayName,
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
        return email;
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private Task<User> LoadUserAsync(string email) =>
        QueryAsync(context => context.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)));
}
