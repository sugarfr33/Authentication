using System.Security.Claims;
using Auth.Api.Endpoints;
using Auth.Api.Security;
using Auth.Services.Passwords;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// Test-only endpoints under /api/v1/__test, mapped through the real IEndpointModule hook so they pass the whole
/// pipeline (CORS, authentication, CSRF/origin protection, authorization). They do not exist in the product.
/// </summary>
internal sealed class TestEndpoints : IEndpointModule
{
    public const string Prefix = "/api/v1/__test";

    /// <summary>Every policy of the API: one per permission plus the Admin role policy.</summary>
    public static readonly IReadOnlyList<string> PolicyNames = [.. Auth.Contracts.AuthPermissions.All, Auth.Contracts.AuthPolicies.AdminRole];

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder test = api.MapGroup("/__test");

        test.MapGet("/ping", () => Results.Ok(new { pong = true }));

        // Stands in for the T13 login: issues both cookies for the seeded user. The body carries no token.
        test.MapPost("/session", async (ITokenService tokens, IRefreshTokenService refresh, ICookieWriter cookies, HttpContext http, CancellationToken cancellationToken) =>
        {
            IssuedRefreshToken refreshToken = await refresh.IssueAsync(
                ApiFixture.UserId, null, new RefreshContext("203.0.113.1", http.Request.Headers.UserAgent.ToString()), cancellationToken);
            AccessToken access = await tokens.CreateAccessTokenAsync(
                new AccessTokenRequest(ApiFixture.UserId, "api.user@example.test", "Api User", ["User"], ["users.read"], ApiFixture.Issuer, null, refreshToken.FamilyId),
                cancellationToken);

            cookies.WriteAccessToken(http.Response, access);
            cookies.WriteRefreshToken(http.Response, refreshToken);
            return Results.Ok(new { ok = true });
        });

        test.MapGet("/me", (ClaimsPrincipal user) => Results.Ok(new
        {
            sub = user.FindFirst("sub")?.Value,
            isUser = user.IsInRole("User"),
            name = user.Identity?.Name,
        })).RequireAuthorization();

        test.MapMethods("/echo", [HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete], () => Results.Ok(new { echoed = true }));

        test.MapPost("/protected", () => Results.Ok(new { done = true })).RequireAuthorization();

        // T16: one GET per policy, to prove the allow/deny matrix through the real pipeline.
        foreach (string policy in PolicyNames)
        {
            test.MapGet("/policy/" + policy, () => Results.Ok(new { allowed = true })).RequireAuthorization(policy);
        }

        // Rate-limit target (mapped to Login by the fixture). Echoes what it read, to prove the body survives the account-key reader.
        test.MapPost("/login", async (HttpRequest request) =>
        {
            using StreamReader reader = new(request.Body);
            string body = await reader.ReadToEndAsync();
            return Results.Ok(new { length = body.Length });
        });

        test.MapPost("/busy", IResult () => throw new PasswordHashingBusyException());

        test.MapPost("/logout", (ICookieWriter cookies, HttpContext http) =>
        {
            cookies.ClearAuthCookies(http.Response);
            return Results.NoContent();
        });
    }
}
