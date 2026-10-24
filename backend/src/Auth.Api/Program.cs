using System.Diagnostics;
using System.Globalization;
using Auth.Api.Endpoints;
using Auth.Api.Health;
using Auth.Api.Hosting;
using Auth.Api.Logging;
using Auth.Api.RateLimiting;
using Auth.Api.Security;
using Auth.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Auth.Services;
using Auth.Services.ClientApplications;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Serilog;
using Serilog.Events;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

HostingGuards.EnsureAllowedHostsRestricted(builder.Configuration, builder.Environment);
HostingGuards.EnsureBrowserProtectionSafe(builder.Configuration, builder.Environment);
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

// Client-application origins must be https outside Development (http only for loopback).
builder.Services.AddSingleton(new ClientApplicationOriginOptions { RequireHttps = !builder.Environment.IsDevelopment() });

// Optional overrides of the Services defaults: concurrent Argon2 operations and lockout thresholds.
builder.Services.AddSingleton(builder.Configuration.GetSection("PasswordHashing").Get<PasswordHashingLimits>() ?? new PasswordHashingLimits());
builder.Services.AddSingleton(builder.Configuration.GetSection("Lockout").Get<LockoutOptions>() ?? new LockoutOptions());
builder.Services.AddAuthServices(builder.Configuration);
builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
    context.ProblemDetails.Extensions["traceId"] = Activity.Current?.Id ?? context.HttpContext.TraceIdentifier);
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddHealthChecks().AddCheck<DatabaseReadinessCheck>("database", tags: ["ready"]);

// Cookie transport (T10): tokens only ever travel in HttpOnly, Secure cookies.
builder.Services.AddOptions<AuthCookieOptions>()
    .Bind(builder.Configuration.GetSection(AuthCookieOptions.SectionName))
    .Validate(options => options.IsValid(), "AuthCookies is invalid: AccessSameSite must be Lax or Strict, RefreshPath must start with /, Domain must be a bare host.")
    .ValidateOnStart();
builder.Services.AddOptions<BrowserProtectionOptions>().Bind(builder.Configuration.GetSection(BrowserProtectionOptions.SectionName));
builder.Services.AddSingleton<ICookieWriter, CookieWriter>();
builder.Services.AddAuthentication(AccessTokenCookieHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, AccessTokenCookieHandler>(AccessTokenCookieHandler.SchemeName, configureOptions: null);
builder.Services.AddAuthorization();

// CSRF: antiforgery tokens bound to the user; the request token reaches script via the readable XSRF-TOKEN cookie.
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = AuthCookieNames.XsrfHeader;
    options.Cookie.Name = AuthCookieNames.Antiforgery;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
    options.SuppressXFrameOptionsHeader = true;
});

// CORS: exact origins from active client applications (plus trusted origins), credentials allowed, never a wildcard.
// Rate limiting (T11): per IP and per account on the auth paths. Forwarded headers only from configured proxies.
builder.Services.AddAuthRateLimiting(builder.Configuration);
bool behindProxy = builder.Services.ConfigureForwardedHeaders(builder.Configuration);

builder.Services.AddCors();
builder.Services.AddSingleton<ICorsPolicyProvider, ClientApplicationCorsPolicyProvider>();

WebApplication app = builder.Build();

if (behindProxy)
{
    app.UseForwardedHeaders();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseExceptionHandler();
app.UseStatusCodePages();
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseSerilogRequestLogging();
app.UseCors();
app.UseMiddleware<AccountKeyMiddleware>();
app.UseRateLimiter();
app.UseAuthentication();
app.UseMiddleware<BrowserProtectionMiddleware>();
app.UseAuthorization();

// Liveness: the process answers. Readiness: dependencies (the database) answer. Bodies are just the status word.
app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });

app.MapWellKnownEndpoints();

// Versioned API surface: every registered endpoint module is mapped under /api/v1 (real modules arrive with T13).
RouteGroupBuilder api = app.MapGroup("/api/v1");
foreach (IEndpointModule module in app.Services.GetServices<IEndpointModule>())
{
    module.Map(api);
}

app.Run();

/// <summary>Entry point; public so integration tests can host the app with WebApplicationFactory.</summary>
public partial class Program;
