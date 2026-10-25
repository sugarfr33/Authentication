using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Accounts;
using Auth.Services.ClientApplications;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Auth.Services.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Services;

/// <summary>T18: the client application registry against SQL Express: writes, CORS source, deactivation, bootstrap.</summary>
public sealed class ClientApplicationRegistryTests : RepositoryTestBase, IAsyncDisposable
{
    private readonly ServiceProvider services;

    public ClientApplicationRegistryTests(SqlServerDatabaseFixture database)
        : base(database)
    {
        services = Build(database.ConnectionString);
    }

    [Fact]
    public async Task Created_applications_are_audited_listed_and_their_ids_and_audiences_are_unique()
    {
        ClientApplicationRequest request = Request();

        ClientApplicationResult created = await RegistryAsync(r => r.CreateAsync(request, true, AuditContext.None, Ct));
        ClientApplicationResult sameClientId = await RegistryAsync(r => r.CreateAsync(request with { Audience = "api://other-" + Guid.NewGuid().ToString("N") }, true, AuditContext.None, Ct));
        ClientApplicationResult sameAudience = await RegistryAsync(r => r.CreateAsync(request with { ClientId = "other-" + Guid.NewGuid().ToString("N")[..8] }, true, AuditContext.None, Ct));

        ClientApplicationResponse app = Assert.IsType<ClientApplicationResponse>(created.Application);
        Assert.True(app.IsActive && app.RequirePkce);
        Assert.Equal(["https://" + request.ClientId + ".example.com"], app.AllowedOrigins);
        Assert.Contains(await RegistryAsync(r => r.ListAsync(Ct)), a => a.Id == app.Id);
        Assert.Equal((AuthError.ValidationFailed, true), (sameClientId.Error!.Value, sameClientId.Errors.ContainsKey("clientId")));
        Assert.Equal((AuthError.ValidationFailed, true), (sameAudience.Error!.Value, sameAudience.Errors.ContainsKey("audience")));
        AuditLog audit = Assert.Single(await AuditAsync(AuditEventType.AppCreated, app.Id));
        Assert.Equal("{\"app\":\"" + app.Id.ToString("D") + "\",\"source\":\"registry\"}", audit.Detail);
    }

    [Fact]
    public async Task Invalid_settings_are_refused_without_a_row_and_updates_cannot_change_the_client_id()
    {
        ClientApplicationResult wildcard = await RegistryAsync(r => r.CreateAsync(Request() with { AllowedOrigins = ["https://*.example.com"] }, true, AuditContext.None, Ct));
        ClientApplicationResponse app = (await RegistryAsync(r => r.CreateAsync(Request(), true, AuditContext.None, Ct))).Application!;

        ClientApplicationResult renamed = await RegistryAsync(r => r.UpdateAsync(app.Id, Request() with { ClientId = "renamed-app" }, AuditContext.None, Ct));
        ClientApplicationResult missing = await RegistryAsync(r => r.UpdateAsync(Guid.NewGuid(), Request(), AuditContext.None, Ct));

        Assert.True(wildcard.Errors.ContainsKey("allowedOrigins"));
        Assert.True(renamed.Errors.ContainsKey("clientId"));
        Assert.Equal(AuthError.NotFound, missing.Error);
    }

    /// <summary>T18 audit M1: two creates racing for one audience both pass the pre-check; the unique index lets one win.</summary>
    [Fact]
    public async Task Concurrent_creates_with_the_same_audience_give_exactly_one_application()
    {
        AudienceGate gate = new(2);
        await using ServiceProvider gated = Build(Database.ConnectionString, gate);
        ClientApplicationRequest first = Request();
        ClientApplicationRequest second = first with { ClientId = "rival-" + Guid.NewGuid().ToString("N")[..10], Audience = first.Audience.ToUpperInvariant() + "/" };

        ClientApplicationResult[] results = await Task.WhenAll(CreateInAsync(gated, first), CreateInAsync(gated, second));

        Assert.Single(results, r => r.IsSuccess);
        ClientApplicationResult loser = Assert.Single(results, r => !r.IsSuccess);
        Assert.True(loser.Errors.ContainsKey("audience"));
        Assert.Equal(2, gate.Arrived);
    }

    /// <summary>T18 audit L5: a new audience ends the application's sessions; other changes only refresh caches.</summary>
    [Fact]
    public async Task Changing_the_audience_ends_the_applications_sessions_but_changing_origins_does_not()
    {
        ClientApplicationRequest request = Request();
        ClientApplicationResponse app = (await RegistryAsync(r => r.CreateAsync(request, true, AuditContext.None, Ct))).Application!;
        User user = TestData.User();
        user.EmailVerified = true;
        await SeedAsync(user);
        Guid family = (await SessionAsync(user.Id, app.ClientId)).Value!.RefreshToken.FamilyId;
        ISessionLiveness liveness = services.GetRequiredService<ISessionLiveness>();

        await RegistryAsync(r => r.UpdateAsync(app.Id, request with { AllowedOrigins = ["https://other-" + request.ClientId + ".example.com"] }, AuditContext.None, Ct));
        bool liveAfterOriginChange = await liveness.IsLiveAsync(user.Id, family, Ct);
        ClientApplicationResult moved = await RegistryAsync(r => r.UpdateAsync(app.Id, request with { Audience = request.Audience + "-v2" }, AuditContext.None, Ct));

        Assert.True(liveAfterOriginChange);
        Assert.Equal(request.Audience + "-v2", moved.Application!.Audience);
        Assert.False(await liveness.IsLiveAsync(user.Id, family, Ct));
        Assert.Contains(await AuditAsync(AuditEventType.AppUpdated, app.Id), a => a.Detail!.EndsWith("\"revoked\":1}", StringComparison.Ordinal));
    }

    /// <summary>CORS reflects exactly the registered active origins, and a change is immediate on this instance.</summary>
    [Fact]
    public async Task The_CORS_list_follows_the_registry_at_once_on_this_instance()
    {
        IClientApplicationOriginProvider origins = services.GetRequiredService<IClientApplicationOriginProvider>();
        ClientApplicationRequest request = Request();
        string origin = request.AllowedOrigins[0];
        Assert.DoesNotContain(origin, await origins.GetAllowedOriginsAsync(Ct));

        ClientApplicationResponse inactive = (await RegistryAsync(r => r.CreateAsync(request, false, AuditContext.None, Ct))).Application!;
        bool listedWhileInactive = (await origins.GetAllowedOriginsAsync(Ct)).Contains(origin);
        await RegistryAsync(r => r.ActivateAsync(inactive.Id, AuditContext.None, Ct));
        bool listedWhenActive = (await origins.GetAllowedOriginsAsync(Ct)).Contains(origin);
        string moved = "https://moved-" + request.ClientId + ".example.com";
        await RegistryAsync(r => r.UpdateAsync(inactive.Id, request with { AllowedOrigins = [moved] }, AuditContext.None, Ct));
        IReadOnlySet<string> afterUpdate = await origins.GetAllowedOriginsAsync(Ct);
        await RegistryAsync(r => r.DeactivateAsync(inactive.Id, AuditContext.None, Ct));
        bool listedAfterDeactivation = (await origins.GetAllowedOriginsAsync(Ct)).Contains(moved);

        Assert.False(listedWhileInactive);
        Assert.True(listedWhenActive);
        Assert.Contains(moved, afterUpdate);
        Assert.DoesNotContain(origin, afterUpdate);
        Assert.False(listedAfterDeactivation);
        Assert.Contains(await AuditAsync(AuditEventType.AppUpdated, inactive.Id), a => a.Detail!.Contains("\"active\":true", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Deactivation_ends_the_applications_sessions_and_it_cannot_get_new_tokens()
    {
        ClientApplicationResponse app = (await RegistryAsync(r => r.CreateAsync(Request(), true, AuditContext.None, Ct))).Application!;
        User user = TestData.User();
        user.EmailVerified = true;
        await SeedAsync(user);
        Result<SignedIn> session = await SessionAsync(user.Id, app.ClientId);
        Guid family = session.Value!.RefreshToken.FamilyId;
        ISessionLiveness liveness = services.GetRequiredService<ISessionLiveness>();
        Assert.True(await liveness.IsLiveAsync(user.Id, family, Ct));

        Assert.True(await RegistryAsync(r => r.DeactivateAsync(app.Id, AuditContext.None, Ct)));

        Assert.False(await liveness.IsLiveAsync(user.Id, family, Ct));
        Assert.All(await WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.FamilyId == family).ToListAsync()), t => Assert.Equal(RefreshTokenRevokedReason.Admin, t.RevokedReason));
        Assert.Equal(AuthError.InvalidClient, (await SessionAsync(user.Id, app.ClientId)).Error);
        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            RotationResult rotation = await scope.ServiceProvider.GetRequiredService<IRefreshTokenService>().RotateAsync(session.Value.RefreshToken.Token, new RefreshContext("203.0.113.1", "tests"), Ct);
            Assert.NotEqual(RotationStatus.Rotated, rotation.Status);
            Assert.Null(rotation.Token);
            await Assert.ThrowsAsync<InactiveClientApplicationException>(() => scope.ServiceProvider.GetRequiredService<IRefreshTokenService>().IssueAsync(user.Id, app.Id, new RefreshContext("203.0.113.1", "tests"), Ct));
        }

        AuditLog audit = Assert.Single(await AuditAsync(AuditEventType.AppDeactivated, app.Id));
        Assert.Equal("{\"app\":\"" + app.Id.ToString("D") + "\",\"revoked\":1}", audit.Detail);
        Assert.Equal(AuthError.InvalidClient, (await SessionAsync(user.Id, "no-such-client")).Error);
    }

    /// <summary>Bootstrap only while no application exists (own empty throwaway database), then never again.</summary>
    [Fact]
    public async Task Bootstrap_registers_the_first_application_once_and_only_into_an_empty_registry()
    {
        string connectionString = TestDatabaseNames.WithUniqueDatabase(Database.ConnectionString, "CentralAuth_AppSeed");
        SqlServerDatabaseFixture.EnsureThrowawayDatabase(connectionString);
        await using ServiceProvider isolated = Build(connectionString);
        await using (AsyncServiceScope scope = isolated.CreateAsyncScope())
        {
            AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await context.Database.EnsureDeletedAsync(Ct);
            await context.Database.MigrateAsync(Ct);
        }

        try
        {
            ClientApplicationBootstrapOptions options = new()
            {
                ClientId = "central-spa",
                Name = "Central auth SPA",
                Audience = "api://central-spa",
                AllowedOrigins = ["https://login.example.com"],
            };

            ClientApplicationBootstrapOutcome invalid = await BootstrapAsync(isolated, new ClientApplicationBootstrapOptions { ClientId = "central-spa", Name = "x", Audience = "https://auth.example.test", AllowedOrigins = ["*"] });
            ClientApplicationBootstrapOutcome[] racing = await Task.WhenAll(BootstrapAsync(isolated, options), BootstrapAsync(isolated, options));
            ClientApplicationBootstrapOutcome first = racing.Contains(ClientApplicationBootstrapOutcome.Created) ? ClientApplicationBootstrapOutcome.Created : racing[0];
            Assert.Contains(racing, o => o == ClientApplicationBootstrapOutcome.ApplicationsExist);
            ClientApplicationBootstrapOutcome second = await BootstrapAsync(isolated, options);
            ClientApplicationBootstrapOutcome other = await BootstrapAsync(isolated, new ClientApplicationBootstrapOptions { ClientId = "another-spa", Name = "Other", Audience = "api://other" });

            Assert.Equal(ClientApplicationBootstrapOutcome.Invalid, invalid);
            Assert.Equal(ClientApplicationBootstrapOutcome.Created, first);
            Assert.Equal(ClientApplicationBootstrapOutcome.ApplicationsExist, second);
            Assert.Equal(ClientApplicationBootstrapOutcome.ApplicationsExist, other);
            await using AsyncServiceScope check = isolated.CreateAsyncScope();
            AuthDbContext db = check.ServiceProvider.GetRequiredService<AuthDbContext>();
            ClientApplication seeded = Assert.Single(await db.ClientApplication.AsNoTracking().ToListAsync(Ct));
            Assert.Equal(("central-spa", true), (seeded.ClientId, seeded.IsActive));
            Assert.Single(await db.AuditLog.AsNoTracking().Where(a => a.EventType == nameof(AuditEventType.AppCreated) && a.Detail!.Contains("bootstrap")).ToListAsync(Ct));
        }
        finally
        {
            await using AsyncServiceScope scope = isolated.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureDeletedAsync(Ct);
        }
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private static ServiceProvider Build(string connectionString, AudienceGate? gate = null)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CentralAuth"] = connectionString,
                ["Auth:Issuer"] = "https://auth.example.test",
            })
            .Build();
        ServiceCollection collection = new();
        collection.AddSingleton(new PasswordHashingOptions { MemorySizeKiB = 1024, Iterations = 1, Parallelism = 1 });
        collection.AddSingleton(new SessionLivenessOptions { CacheDuration = TimeSpan.FromSeconds(30) });
        collection.AddSingleton<IEmailSender>(new CapturingEmailSender());
        collection.AddAuthServices(configuration);
        collection.AddSingleton<ITokenService, StubTokenService>();
        if (gate is not null)
        {
            ServiceDescriptor real = collection.Last(d => d.ServiceType == typeof(Auth.DAL.Repositories.IClientApplicationRepository));
            collection.AddScoped<Auth.DAL.Repositories.IClientApplicationRepository>(sp => new GatedApplications(
                (Auth.DAL.Repositories.IClientApplicationRepository)ActivatorUtilities.CreateInstance(sp, real.ImplementationType!),
                gate));
        }

        return collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private static async Task<ClientApplicationBootstrapOutcome> BootstrapAsync(ServiceProvider provider, ClientApplicationBootstrapOptions options)
    {
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().BootstrapAsync(options, CancellationToken.None);
    }

    private static async Task<ClientApplicationResult> CreateInAsync(ServiceProvider provider, ClientApplicationRequest request)
    {
        await Task.Yield();
        await using AsyncServiceScope scope = provider.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>().CreateAsync(request, true, AuditContext.None, CancellationToken.None);
    }

    private static ClientApplicationRequest Request()
    {
        string id = "app-" + Guid.NewGuid().ToString("N")[..10];
        return new ClientApplicationRequest(id, "Test " + id, "api://" + id, ["https://" + id + ".example.com"], ["https://" + id + ".example.com/callback"], []);
    }

    private async Task<T> RegistryAsync<T>(Func<IClientApplicationRegistry, Task<T>> action)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<IClientApplicationRegistry>());
    }

    private async Task<Result<SignedIn>> SessionAsync(Guid userId, string clientId)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IClientSessionService>().StartAsync(userId, clientId, Guid.NewGuid(), new RefreshContext("203.0.113.1", "tests"), AuditContext.None, Ct);
    }

    private Task<List<AuditLog>> AuditAsync(AuditEventType type, Guid applicationId)
    {
        string name = type.ToString();
        string id = applicationId.ToString("D");
        return WithContextAsync(c => c.AuditLog.AsNoTracking().Where(a => a.EventType == name && a.Detail!.Contains(id)).ToListAsync());
    }

    private async Task<T> WithContextAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    /// <summary>Holds every audience pre-check until all racers have made it, so they all pass it before inserting.</summary>
    private sealed class AudienceGate(int racers)
    {
        private readonly TaskCompletionSource open = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int arrived;

        public int Arrived => Volatile.Read(ref arrived);

        public async Task WaitAsync()
        {
            if (Interlocked.Increment(ref arrived) >= racers)
            {
                open.TrySetResult();
            }

            await open.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class GatedApplications(Auth.DAL.Repositories.IClientApplicationRepository inner, AudienceGate gate) : Auth.DAL.Repositories.IClientApplicationRepository
    {
        public Task<ClientApplication?> GetByIdAsync(Guid id, CancellationToken cancellationToken) => inner.GetByIdAsync(id, cancellationToken);

        public Task<ClientApplication?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken) => inner.GetByClientIdAsync(clientId, cancellationToken);

        public Task<IReadOnlyList<ClientApplication>> GetActiveAsync(CancellationToken cancellationToken) => inner.GetActiveAsync(cancellationToken);

        public Task<IReadOnlyList<ClientApplication>> GetAllAsync(CancellationToken cancellationToken) => inner.GetAllAsync(cancellationToken);

        public Task<bool> AnyAsync(CancellationToken cancellationToken) => inner.AnyAsync(cancellationToken);

        public async Task<bool> IsAudienceInUseAsync(string audience, Guid? exceptId, CancellationToken cancellationToken)
        {
            bool inUse = await inner.IsAudienceInUseAsync(audience, exceptId, cancellationToken);
            await gate.WaitAsync();
            return inUse;
        }

        public Task AddAsync(ClientApplication application, CancellationToken cancellationToken) => inner.AddAsync(application, cancellationToken);

        public void Update(ClientApplication application) => inner.Update(application);
    }

    /// <summary>The shared test database has no signing key; signing is covered by the API tests.</summary>
    private sealed class StubTokenService : ITokenService
    {
        public Task<AccessToken> CreateAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new AccessToken("test-jwt", DateTime.UtcNow.AddMinutes(10)));

        public Task<TokenValidationParameters> GetValidationParametersAsync(string? audience, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<TokenValidationResult> ValidateAsync(string jwt, string? audience, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<TokenValidationResult> ValidateIgnoringLifetimeAsync(string jwt, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
