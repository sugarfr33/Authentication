using System.Security.Claims;
using Auth.Client;
using Auth.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Auth.SampleApi;

/// <summary>
/// A second API that trusts central auth through <c>AddCentralAuth</c> only (docs/t22-client-extension.md section 8).
/// An explicit, namespaced entry point so tests can host it next to Auth.Api's global Program.
/// </summary>
public sealed class SampleApiProgram
{
    /// <summary>The application role (prefixed per client, T18) that <c>/api/reports</c> requires.</summary>
    public const string ReaderRole = "reader";

    private SampleApiProgram()
    {
    }

    public static void Main(string[] args) => Build(args).Run();

    public static WebApplication Build(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        builder.Services.AddCentralAuth(builder.Configuration.GetSection("CentralAuth"));
        // Default deny: an endpoint without its own rule still needs a valid token (/health opts out explicitly).
        builder.Services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy("Reader", policy => policy.RequireAuthenticatedUser().RequireAssertion(context =>
            {
                string? clientId = context.User.FindFirst(AuthClaimTypes.ClientId)?.Value;
                return clientId is not null && context.User.IsInRole(AuthRoles.ApplicationRole(clientId, ReaderRole));
            }));

        // No CORS on purpose: this sample is called server to server or from its own origin. Add a CORS policy listing
        // exact origins if a browser app on another origin must call it.
        WebApplication app = builder.Build();
        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
            app.UseHttpsRedirection();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
        app.MapGet("/api/me", (ClaimsPrincipal user) => Results.Ok(new SampleMeResponse(
            user.FindFirst(AuthClaimTypes.Subject)?.Value,
            user.Identity?.Name,
            [.. user.FindAll(AuthClaimTypes.Role).Select(c => c.Value)],
            [.. user.FindAll(AuthClaimTypes.Permission).Select(c => c.Value)]))).RequireAuthorization();
        app.MapGet("/api/reports", (IOptionsMonitor<CentralAuthOptions> options) =>
            Results.Ok(new { client = options.Get(CentralAuthDefaults.AuthenticationScheme).ClientId, reports = Array.Empty<string>() })).RequireAuthorization("Reader");
        // No rule of its own: the fallback policy (authenticated user) protects it.
        app.MapPost("/api/notes", () => Results.NoContent());
        return app;
    }
}

/// <summary>What <c>/api/me</c> answers: the caller as central auth described them.</summary>
public sealed record SampleMeResponse(string? Subject, string? Name, IReadOnlyList<string> Roles, IReadOnlyList<string> Permissions);
