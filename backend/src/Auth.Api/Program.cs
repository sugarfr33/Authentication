using System.Diagnostics;
using System.Globalization;
using Auth.Api.Endpoints;
using Auth.Api.Health;
using Auth.Api.Hosting;
using Auth.Api.Logging;
using Auth.Services;
using Serilog;
using Serilog.Events;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

HostingGuards.EnsureAllowedHostsRestricted(builder.Configuration, builder.Environment);
builder.WebHost.ConfigureKestrel(kestrel => kestrel.AddServerHeader = false);

// Secrets (connection string, signing keys) come only from environment variables or User Secrets (Development);
// appsettings files hold no secrets. See appsettings.Example.json.
builder.Services.AddSerilog((services, logger) => logger
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .MinimumLevel.Override("Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware", LogEventLevel.Fatal)
    .Enrich.FromLogContext()
    .Enrich.With<RedactionEnricher>()
    .WriteTo.Console(formatProvider: CultureInfo.InvariantCulture));

builder.Services.AddAuthServices(builder.Configuration);
builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
    context.ProblemDetails.Extensions["traceId"] = Activity.Current?.Id ?? context.HttpContext.TraceIdentifier);
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddHealthChecks().AddCheck<DatabaseReadinessCheck>("database", tags: ["ready"]);

WebApplication app = builder.Build();

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseExceptionHandler();
app.UseStatusCodePages();
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseSerilogRequestLogging();

// Liveness: the process answers. Readiness: dependencies (the database) answer. Bodies are just the status word.
app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

app.MapWellKnownEndpoints();

// Versioned API surface. Endpoints arrive with T10+ (cookies, auth flows).
app.MapGroup("/api/v1");

app.Run();

/// <summary>Entry point; public so integration tests can host the app with WebApplicationFactory.</summary>
public partial class Program;
