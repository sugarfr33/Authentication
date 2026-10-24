using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Auth.Api.Endpoints;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog.Core;
using Serilog.Events;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// Hosts the real Auth.Api (Program) in the Production environment against its own throwaway CentralAuth_Api_run{id}_Test
/// database (migrated, with one real ES256 signing key), with every log event captured by an in-memory sink.
/// </summary>
public sealed class ApiFixture : IAsyncLifetime
{
    public const string Host = "auth.example.test";
    public const string Issuer = "https://auth.example.test";
    public const string SigningKid = "api-k1";
    public const string ThrowPath = "/__test/throw";
    public const string TestRemoteIp = "10.0.0.1";
    public const string ThrowProbe = "probe-exception-text-C:/secret/path";

    public const string AppOrigin = "https://app.example.test";
    public const string InactiveOrigin = "https://inactive.example.test";
    public const string InsecureOrigin = "http://insecure.example.test";
    public const string LoopbackOrigin = "http://localhost:5173";
    public static readonly Guid UserId = Guid.Parse("0b9f3c3e-6a1d-4e8b-9c2a-5d7e1f2a3b4c");

    private const string PrivateKeyReference = "api-test-key";

    public ApiFixture()
    {
        string baseConnection = Environment.GetEnvironmentVariable(SqlServerDatabaseFixture.ConnectionStringVariable) is { Length: > 0 } fromEnvironment
            ? fromEnvironment
            : @"Server=.\SQLEXPRESS;Database=CentralAuth_Test;Trusted_Connection=True;TrustServerCertificate=True;";
        ConnectionString = TestDatabaseNames.WithUniqueDatabase(baseConnection, "CentralAuth_Api");
        MissingDatabaseConnectionString = TestDatabaseNames.WithUniqueDatabase(baseConnection, "CentralAuth_Missing");

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PrivateKeyPem = key.ExportPkcs8PrivateKeyPem();
        Factory = new ApiFactory(this, Environments.Production);
    }

    public string ConnectionString { get; }

    public string MissingDatabaseConnectionString { get; }

    public string PrivateKeyPem { get; }

    public LogSink Logs { get; } = new();

    /// <summary>Every account email the app sends (the fixture replaces the production sender).</summary>
    public Services.CapturingEmailSender Emails { get; } = new();

    public ApiFactory Factory { get; }

    public HttpClient CreateHttpsClient(WebApplicationFactory<Program>? factory = null) =>
        (factory ?? Factory).CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://" + Host), AllowAutoRedirect = false });

    public async Task InitializeAsync()
    {
        await using (AuthDbContext context = NewContext(ConnectionString))
        {
            SqlServerDatabaseFixture.EnsureThrowawayDatabase(ConnectionString);
            await context.Database.EnsureDeletedAsync();
            await context.Database.MigrateAsync();
            await SeedAsync(context);
        }

        await using AsyncServiceScope scope = Factory.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ISigningKeyRotation>()
            .AddKeyAsync(SigningKid, SigningKeyAlgorithm.ES256, PrivateKeyReference, DateTime.UtcNow, CancellationToken.None);
    }

    public async Task DisposeAsync()
    {
        await Factory.DisposeAsync();
        SqlServerDatabaseFixture.EnsureThrowawayDatabase(ConnectionString);
        await using AuthDbContext context = NewContext(ConnectionString);
        await context.Database.EnsureDeletedAsync();
    }

    /// <summary>Every setting the tests need. Exception details are switched ON to prove Production ignores the flag.</summary>
    internal Dictionary<string, string?> Settings() => new()
    {
        ["ConnectionStrings:CentralAuth"] = ConnectionString,
        ["Auth:Issuer"] = Issuer,
        ["AllowedHosts"] = Host,
        ["https_port"] = "443",
        ["Errors:IncludeExceptionDetails"] = "true",
        ["Secrets:" + PrivateKeyReference] = PrivateKeyPem,
        ["RateLimiting:Paths:" + TestEndpoints.Prefix + "/login"] = "Login",
        ["Serilog:MinimumLevel:Default"] = "Verbose",
        ["Serilog:MinimumLevel:Override:Microsoft"] = "Verbose",
        ["Serilog:MinimumLevel:Override:Microsoft.AspNetCore"] = "Verbose",
        ["Serilog:MinimumLevel:Override:Microsoft.EntityFrameworkCore"] = "Verbose",
        ["Serilog:MinimumLevel:Override:System"] = "Verbose",
    };

    /// <summary>One user, one active application (AppOrigin) and one inactive application (InactiveOrigin).</summary>
    private static async Task SeedAsync(AuthDbContext context)
    {
        DateTime now = DateTime.UtcNow;
        context.User.Add(new User
        {
            Id = UserId,
            Email = "api.user@example.test",
            NormalizedEmail = "API.USER@EXAMPLE.TEST",
            PasswordHash = "argon2id$placeholder",
            DisplayName = "Api User",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        });
        context.ClientApplication.Add(Application("active-app", AppOrigin, isActive: true, now));
        context.ClientApplication.Add(Application("inactive-app", InactiveOrigin, isActive: false, now));
        context.ClientApplication.Add(Application("insecure-app", InsecureOrigin + "\", \"" + LoopbackOrigin, isActive: true, now));
        await context.SaveChangesAsync();
    }

    private static ClientApplication Application(string clientId, string origin, bool isActive, DateTime now) => new()
    {
        ClientId = clientId,
        Name = clientId,
        Audience = "api://" + clientId,
        AllowedOrigin = "[\"" + origin + "\"]",
        RedirectUri = "[]",
        PostLogoutRedirectUri = "[]",
        IsActive = isActive,
        CreatedUtc = now,
        UpdatedUtc = now,
    };

    private static AuthDbContext NewContext(string connectionString)
    {
        DbContextOptionsBuilder<AuthDbContext> builder = new();
        AuthDbContext.UseAuthSqlServer(builder, connectionString);
        return new AuthDbContext(builder.Options);
    }

    private static string WithDatabase(string connectionString, string database) =>
        new SqlConnectionStringBuilder(connectionString) { InitialCatalog = database }.ConnectionString;

    public sealed class ApiFactory(ApiFixture fixture, string environment) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            foreach (KeyValuePair<string, string?> setting in fixture.Settings())
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(fixture.Settings()));
            builder.ConfigureServices(services =>
            {
                services.AddSingleton<ILogEventSink>(fixture.Logs);
                services.AddSingleton<Auth.Services.Accounts.IEmailSender>(fixture.Emails);
                services.AddSingleton(new Auth.Services.Passwords.PasswordHashingOptions { MemorySizeKiB = 1024, Iterations = 1, Parallelism = 1 });
                services.AddSingleton<IStartupFilter, RemoteIpFilter>();
                services.AddSingleton<IStartupFilter, ThrowingEndpointFilter>();
                services.AddSingleton<IEndpointModule, TestEndpoints>();
            });
        }
    }

    /// <summary>TestServer has no remote IP; give every request 'TestRemoteIp' (a stand-in for the proxy in front of the API).</summary>
    private sealed class RemoteIpFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress ??= System.Net.IPAddress.Parse(TestRemoteIp);
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    /// <summary>Adds a test-only endpoint after the app pipeline that throws an exception carrying a probe text.</summary>
    private sealed class ThrowingEndpointFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            next(app);
            app.Map(ThrowPath, branch => branch.Run(_ => throw new InvalidOperationException(ThrowProbe)));
        };
    }

    /// <summary>Collects every Serilog event after redaction.</summary>
    public sealed class LogSink : ILogEventSink
    {
        private readonly List<LogEvent> events = [];

        public IReadOnlyList<LogEvent> Events
        {
            get
            {
                lock (events)
                {
                    return [.. events];
                }
            }
        }

        /// <summary>Everything a sink could write: rendered message, every property and the exception.</summary>
        public IReadOnlyList<string> Texts => Events
            .Select(e => e.RenderMessage(CultureInfo.InvariantCulture) + " " + string.Join(" ", e.Properties.Select(p => p.Key + "=" + p.Value)) + " " + e.Exception)
            .ToList();

        public void Emit(LogEvent logEvent)
        {
            lock (events)
            {
                events.Add(logEvent);
            }
        }
    }
}

[CollectionDefinition(Name)]
public sealed class ApiTestGroup : ICollectionFixture<ApiFixture>
{
    public const string Name = "Api";
}

internal static class HttpExtensions
{
    public static string Header(this HttpResponseMessage response, string name) =>
        response.Headers.NonValidated.TryGetValues(name, out HeaderStringValues values) || response.Content.Headers.NonValidated.TryGetValues(name, out values)
            ? string.Join(", ", values)
            : string.Empty;

    public static bool HasHeader(this HttpResponseMessage response, string name) =>
        response.Headers.NonValidated.Contains(name) || response.Content.Headers.NonValidated.Contains(name);
}
