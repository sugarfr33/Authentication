using System.Diagnostics;
using System.Globalization;
using Auth.Api.Email;
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
using Auth.Services.Accounts;
using Auth.Services.Authorization;
using Auth.Services.ClientApplications;
using Auth.Services.OAuth;
using Auth.Services.Passwords;
using Auth.Services.Retention;
using Auth.Services.Security;
using Serilog;
using Serilog.Events;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

HostingGuards.EnsureAllowedHostsRestricted(builder.Configuration, builder.Environment);
HostingGuards.EnsureBrowserProtectionSafe(builder.Configuration, builder.Environment);
HostingGuards.EnsureNoConfiguredLogSinks(builder.Configuration);
builder.WebHost.ConfigureKestrel(kestrel => kestrel.AddServerHeader = false);

// Secrets (connection string, signing keys) come only from environment variables or User Secrets (Development);
// appsettings files hold no secrets. See appsettings.Example.json.
// Every sink is wrapped in ExceptionScrubbingSink (exceptions are redacted copies) and sees events only after the
// RedactionEnricher: the console here, and any sink registered in DI. Sinks cannot come from configuration (guard above).
builder.Services.AddSerilog((services, logger) =>
{
    logger
        .ReadFrom.Configuration(builder.Configuration)
        .MinimumLevel.Override("Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware", LogEventLevel.Fatal)
        .Enrich.FromLogContext()
        .Enrich.With<RedactionEnricher>();
    logger.WriteTo.Sink(Serilog.Configuration.LoggerSinkConfiguration.Wrap(
        sink => new ExceptionScrubbingSink(sink),
        sinks => sinks.Console(formatProvider: CultureInfo.InvariantCulture)));
    foreach (Serilog.Core.ILogEventSink sink in services.GetServices<Serilog.Core.ILogEventSink>())
    {
        logger.WriteTo.Sink(new ExceptionScrubbingSink(sink));
    }
});

// Client-application origins must be https outside Development (http only for loopback).
builder.Services.AddSingleton(new ClientApplicationOriginOptions { RequireHttps = !builder.Environment.IsDevelopment() });

// Optional overrides of the Services defaults: concurrent Argon2 operations and lockout thresholds.
builder.Services.AddSingleton(builder.Configuration.GetSection("PasswordHashing").Get<PasswordHashingLimits>() ?? new PasswordHashingLimits());
builder.Services.AddSingleton((builder.Configuration.GetSection("Lockout").Get<LockoutOptions>() ?? new LockoutOptions()).Validated());
builder.Services.AddSingleton((builder.Configuration.GetSection("RefreshTokens").Get<Auth.Services.Tokens.RefreshTokenOptions>() ?? new Auth.Services.Tokens.RefreshTokenOptions()).Validated());
builder.Services.AddSingleton((builder.Configuration.GetSection(SessionLivenessOptions.SectionName).Get<SessionLivenessOptions>() ?? new SessionLivenessOptions()).Validated());
builder.Services.AddSingleton(builder.Configuration.GetSection(AccountEmailOptions.SectionName).Get<AccountEmailOptions>() ?? new AccountEmailOptions());
builder.Services.AddSingleton<Auth.Services.Audit.IAuditFailureReporter, AuditFailureLog>();
builder.Services.AddAuthServices(builder.Configuration);

// Account emails (T12): a local pickup folder in Development; elsewhere a real provider must replace the refusing sender.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton(builder.Configuration.GetSection(DevelopmentEmailOptions.SectionName).Get<DevelopmentEmailOptions>() ?? new DevelopmentEmailOptions());
    builder.Services.AddSingleton<IEmailSender, PickupDirectoryEmailSender>();
}
else
{
    builder.Services.AddSingleton<IEmailSender, UnconfiguredEmailSender>();
}

builder.Services.AddSingleton<IEndpointModule, AccountEndpoints>();
builder.Services.AddSingleton<IEndpointModule, SessionEndpoints>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<RefreshRejectionLog>();
builder.Services.AddSingleton<LivenessFailureLog>();
builder.Services.AddSingleton<IEndpointModule, PasswordEndpoints>();

// OAuth Authorization Code + PKCE (T19): login UI for users without a session; see docs/authorization-code-pkce.md.
builder.Services.AddSingleton((builder.Configuration.GetSection(OAuthOptions.SectionName).Get<OAuthOptions>() ?? new OAuthOptions()).Validated(requireHttps: !builder.Environment.IsDevelopment()));
builder.Services.AddSingleton<IEndpointModule, OAuthEndpoints>();
builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
    context.ProblemDetails.Extensions["traceId"] = Activity.Current?.Id ?? context.HttpContext.TraceIdentifier);
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddHealthChecks().AddCheck<DatabaseReadinessCheck>("database", tags: ["ready"]);

// Cookie transport (T10): tokens only ever travel in HttpOnly, Secure cookies.
builder.Services.AddOptions<AuthCookieOptions>()
    .Bind(builder.Configuration.GetSection(AuthCookieOptions.SectionName))
    .PostConfigure(options => options.Domain = string.IsNullOrWhiteSpace(options.Domain) ? null : options.Domain)
    .Validate(
        options => options.IsValid(builder.Configuration["Auth:Issuer"]),
        "AuthCookies is invalid: AccessSameSite must be Lax or Strict, RefreshPath must start with /, and Domain (shared-domain mode) must be a lower-case registrable parent of the https Auth:Issuer host: no IP, port, scheme or leading dot, not a public suffix such as co.uk.")
    .ValidateOnStart();
builder.Services.AddOptions<BrowserProtectionOptions>().Bind(builder.Configuration.GetSection(BrowserProtectionOptions.SectionName));
builder.Services.AddSingleton<ICookieWriter, CookieWriter>();
builder.Services.AddAuthentication(AccessTokenCookieHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, AccessTokenCookieHandler>(AccessTokenCookieHandler.SchemeName, configureOptions: null);
builder.Services.AddAuthorization(AuthorizationPolicies.Configure);

// Authorization data (T16): system permissions and roles are seeded at startup (idempotent).
builder.Services.AddSingleton(builder.Configuration.GetSection(AuthorizationSeedOptions.SectionName).Get<AuthorizationSeedOptions>() ?? new AuthorizationSeedOptions());
builder.Services.AddHostedService<AuthorizationSeedOnStartup>();

// Client application registry (T18): the first application (the SPA) can be registered from configuration.
builder.Services.AddSingleton(builder.Configuration.GetSection(ClientApplicationBootstrapOptions.SectionName).Get<ClientApplicationBootstrapOptions>() ?? new ClientApplicationBootstrapOptions());
builder.Services.AddHostedService<ClientApplicationSeedOnStartup>();

// Retention purge (T17): off unless Retention:Enabled; see docs/audit-and-retention.md.
builder.Services.AddSingleton((builder.Configuration.GetSection(RetentionOptions.SectionName).Get<RetentionOptions>() ?? new RetentionOptions()).Validated());
builder.Services.AddHostedService<RetentionPurgeService>();

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
bool warnAboutProxy = !behindProxy && !builder.Environment.IsDevelopment() && !builder.Configuration.GetValue<bool>("ForwardedHeaders:Direct");
builder.Services.AddHostedService<TimingGuardWarmUp>();

builder.Services.AddCors();
builder.Services.AddSingleton<ICorsPolicyProvider, ClientApplicationCorsPolicyProvider>();

WebApplication app = builder.Build();

if (behindProxy)
{
    app.UseForwardedHeaders();
}
else if (warnAboutProxy)
{
    app.UseMiddleware<ProxyMisconfigurationDetector>();
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
app.UseRateLimiter();
app.UseMiddleware<AccountKeyMiddleware>();
app.UseMiddleware<AccountRateLimitMiddleware>();
app.UseMiddleware<DuplicateCookieGuardMiddleware>();
app.UseAuthentication();
app.UseMiddleware<BrowserProtectionMiddleware>();
app.UseAuthorization();

// Liveness: the process answers. Readiness: dependencies (the database) answer. Bodies are just the status word.
app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions { Predicate = _ => false })
    .AllowAnonymous();
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") })
    .AllowAnonymous();

app.MapWellKnownEndpoints();

// Versioned API surface: every registered endpoint module is mapped under /api/v1. Default deny: signed-in users only,
// unless an endpoint says AllowAnonymous() (or names a stricter policy).
RouteGroupBuilder api = app.MapGroup("/api/v1");
api.RequireAuthorization();
foreach (IEndpointModule module in app.Services.GetServices<IEndpointModule>())
{
    module.Map(api);
}

app.Run();

/// <summary>Entry point; public so integration tests can host the app with WebApplicationFactory.</summary>
public partial class Program;
