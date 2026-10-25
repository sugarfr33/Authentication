using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Accounts;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Services;

/// <summary>T15 audit fixes: refresh never orphans a rotation, refuses client-app families, and audits replays precisely.</summary>
public sealed class RefreshServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private readonly ServiceProvider services;
    private readonly Faults faults = new();

    public RefreshServiceTests(SqlServerDatabaseFixture database)
        : base(database)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CentralAuth"] = database.ConnectionString,
                ["Auth:Issuer"] = "https://auth.example.test",
            })
            .Build();
        ServiceCollection collection = new();
        collection.AddSingleton(new PasswordHashingOptions { MemorySizeKiB = 1024, Iterations = 1, Parallelism = 1 });
        collection.AddSingleton<IEmailSender>(new CapturingEmailSender());
        collection.AddAuthServices(configuration);
        collection.AddSingleton(faults);
        collection.AddSingleton<IAuditFailureReporter>(faults);
        collection.AddSingleton<ITokenService, FaultyTokenService>();
        Decorate<IAuditLogRepository>(collection, (sp, inner) => new FaultyAudit(inner, faults));
        Decorate<IRefreshTokenService>(collection, (sp, inner) => new StampChangingRefresh(inner, faults, sp));
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    [Fact]
    public async Task A_failure_before_rotation_leaves_the_presented_token_usable()
    {
        (Guid userId, string token) = await SessionAsync();
        faults.FailMint = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => RefreshAsync(token, "agent-a"));

        faults.FailMint = false;
        RefreshOutcome retry = await RefreshAsync(token, "agent-a");
        Assert.Equal(RotationStatus.Rotated, retry.Status);
        Assert.Equal(userId, retry.Session!.RefreshToken.UserId);
    }

    [Fact]
    public async Task A_failing_audit_write_does_not_lose_the_rotated_session()
    {
        (_, string token) = await SessionAsync();
        faults.FailAudit = true;

        RefreshOutcome outcome = await RefreshAsync(token, "agent-a");

        faults.FailAudit = false;
        Assert.Equal(RotationStatus.Rotated, outcome.Status);
        Assert.Equal([(AuditEventType.TokenRefreshed, nameof(InvalidOperationException))], faults.AuditFailures);
        Assert.Equal(RotationStatus.Rotated, (await RefreshAsync(outcome.Session!.RefreshToken.Token, "agent-a")).Status);
    }

    /// <summary>Reviewer (d): a password change that lands while the token rotates leaves no live successor.</summary>
    [Fact]
    public async Task A_credential_change_during_rotation_revokes_the_new_session()
    {
        (Guid userId, string token) = await SessionAsync();
        faults.ChangeStampDuringRotation = userId;

        RefreshOutcome outcome = await RefreshAsync(token, "agent-a");

        Assert.Equal(RotationStatus.Invalid, outcome.Status);
        Assert.All(await TokensAsync(userId), t => Assert.NotNull(t.RevokedUtc));
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.RefreshRejected) && a.Detail == """{"reason":"credentials_changed"}""");
    }

    [Fact]
    public async Task A_client_application_family_is_refused_and_left_unchanged()
    {
        User user = await SeedUserAsync();
        ClientApplication application = TestData.ClientApplication();
        await SeedAsync(application);
        IssuedRefreshToken issued = await InAppScopeAsync<IRefreshTokenService, IssuedRefreshToken>(s =>
            s.IssueAsync(user.Id, application.Id, new RefreshContext("203.0.113.1", "agent-a"), Ct));

        RefreshOutcome outcome = await RefreshAsync(issued.Token, "agent-a");

        Assert.Equal(RotationStatus.Invalid, outcome.Status);
        Assert.Null(Assert.Single(await TokensAsync(user.Id)).RevokedUtc);
    }

    [Fact]
    public async Task Replaying_an_ended_session_is_rejected_but_only_real_reuse_is_audited_as_reuse()
    {
        (Guid endedUser, string ended) = await SessionAsync();
        await InAppScopeAsync<IRefreshTokenService, int>(s => s.RevokeAllAsync(endedUser, RefreshTokenRevokedReason.Logout, Ct));
        (Guid stolenUser, string stolen) = await SessionAsync();
        RefreshOutcome first = await RefreshAsync(stolen, "owner-agent");

        RefreshOutcome endedReplay = await RefreshAsync(ended, "agent-a");
        RefreshOutcome theft = await RefreshAsync(stolen, "thief-agent");

        Assert.Equal(RotationStatus.Rotated, first.Status);
        Assert.Equal(RotationStatus.ReuseDetected, endedReplay.Status);
        Assert.Equal(RotationStatus.ReuseDetected, theft.Status);
        List<AuditLog> endedAudit = await AuditAsync(endedUser);
        Assert.DoesNotContain(endedAudit, a => a.EventType == nameof(AuditEventType.TokenReuse));
        Assert.Contains(endedAudit, a => a.EventType == nameof(AuditEventType.RefreshRejected) && a.Detail == """{"reason":"ended_session_replayed"}""");
        Assert.Contains(await AuditAsync(stolenUser), a => a.EventType == nameof(AuditEventType.TokenReuse));
    }

    /// <summary>T19 arch M2: the app refresh grant uses the same pipeline, so a failing mint never loses the rotated token.</summary>
    [Fact]
    public async Task An_application_refresh_that_fails_before_rotation_leaves_the_presented_token_usable()
    {
        (Guid userId, ClientApplication application, string token) = await AppSessionAsync();
        faults.FailMint = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => AppRefreshAsync(token, application.ClientId, "agent-a"));

        faults.FailMint = false;
        Result<SignedIn> retry = await AppRefreshAsync(token, application.ClientId, "agent-a");
        Assert.True(retry.IsSuccess);
        Assert.Equal((userId, application.Id), (retry.Value!.RefreshToken.UserId, retry.Value.RefreshToken.ClientApplicationId!.Value));
    }

    /// <summary>T19 arch M2: a password change during an app refresh is detected, as for browser sessions.</summary>
    [Fact]
    public async Task A_credential_change_during_an_application_refresh_revokes_the_new_session()
    {
        (Guid userId, ClientApplication application, string token) = await AppSessionAsync();
        faults.ChangeStampDuringRotation = userId;

        Result<SignedIn> outcome = await AppRefreshAsync(token, application.ClientId, "agent-a");

        Assert.Equal(AuthError.InvalidGrant, outcome.Error);
        Assert.All(await TokensAsync(userId), t => Assert.NotNull(t.RevokedUtc));
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.RefreshRejected)
            && a.Detail!.Contains("credentials_changed", StringComparison.Ordinal) && a.Detail.Contains(application.Id.ToString("D"), StringComparison.Ordinal));
    }

    /// <summary>T19 arch L2: a browser family presented to the app grant is a RefreshRejected with the application, not a code rejection.</summary>
    [Fact]
    public async Task A_browser_family_presented_to_the_application_grant_is_refused_and_audited_as_a_refresh_rejection()
    {
        (Guid userId, string browserToken) = await SessionAsync();
        ClientApplication application = TestData.ClientApplication();
        await SeedAsync(application);

        Result<SignedIn> outcome = await AppRefreshAsync(browserToken, application.ClientId, "agent-a");

        Assert.Equal(AuthError.InvalidGrant, outcome.Error);
        Assert.Null(Assert.Single(await TokensAsync(userId)).RevokedUtc);
        List<AuditLog> audit = await AuditAsync(userId);
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.RefreshRejected) && a.Detail!.Contains("client_mismatch", StringComparison.Ordinal));
        Assert.DoesNotContain(audit, a => a.EventType == nameof(AuditEventType.AuthorizationCodeRejected));
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private Task<Result<SignedIn>> AppRefreshAsync(string token, string clientId, string userAgent) =>
        InAppScopeAsync<Auth.Services.ClientApplications.IClientSessionService, Result<SignedIn>>(s =>
            s.RefreshAsync(token, clientId, new RefreshContext("203.0.113.1", userAgent), new AuditContext("203.0.113.1", userAgent, null), Ct));

    private async Task<(Guid UserId, ClientApplication Application, string Token)> AppSessionAsync()
    {
        User user = await SeedUserAsync();
        ClientApplication application = TestData.ClientApplication();
        await SeedAsync(application);
        IssuedRefreshToken issued = await InAppScopeAsync<IRefreshTokenService, IssuedRefreshToken>(s =>
            s.IssueAsync(user.Id, application.Id, new RefreshContext("203.0.113.1", "owner-agent"), Ct));
        return (user.Id, application, issued.Token);
    }

    private static void Decorate<TService>(IServiceCollection collection, Func<IServiceProvider, TService, TService> decorate)
        where TService : class
    {
        ServiceDescriptor original = collection.Last(d => d.ServiceType == typeof(TService));
        collection.Add(ServiceDescriptor.Describe(
            typeof(TService),
            sp => decorate(sp, (TService)(original.ImplementationFactory?.Invoke(sp) ?? ActivatorUtilities.CreateInstance(sp, original.ImplementationType!))),
            original.Lifetime));
    }

    private Task<RefreshOutcome> RefreshAsync(string token, string userAgent) =>
        InAppScopeAsync<ISignInService, RefreshOutcome>(s => s.RefreshAsync(token, new AuditContext("203.0.113.1", userAgent, null), Ct));

    private async Task<(Guid UserId, string Token)> SessionAsync()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken issued = await InAppScopeAsync<IRefreshTokenService, IssuedRefreshToken>(s =>
            s.IssueAsync(user.Id, null, new RefreshContext("203.0.113.1", "owner-agent"), Ct));
        return (user.Id, issued.Token);
    }

    private async Task<User> SeedUserAsync()
    {
        User user = TestData.User();
        user.EmailVerified = true;
        user.IsActive = true;
        await SeedAsync(user);
        return user;
    }

    private async Task<TResult> InAppScopeAsync<TService, TResult>(Func<TService, Task<TResult>> action)
        where TService : notnull
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    private async Task<List<RefreshToken>> TokensAsync(Guid userId)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AuthDbContext>().RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync();
    }

    private async Task<List<AuditLog>> AuditAsync(Guid userId)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AuthDbContext>().AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync();
    }

    private sealed class Faults : IAuditFailureReporter
    {
        public List<(AuditEventType Type, string ExceptionType)> AuditFailures { get; } = [];

        public void Report(AuditEventType type, string exceptionType) => AuditFailures.Add((type, exceptionType));

        public bool FailMint { get; set; }

        public bool FailAudit { get; set; }

        public Guid? ChangeStampDuringRotation { get; set; }
    }

    private sealed class FaultyTokenService(Faults faults) : ITokenService
    {
        public Task<AccessToken> CreateAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken) =>
            faults.FailMint
                ? throw new InvalidOperationException("Simulated signing failure.")
                : Task.FromResult(new AccessToken("test-jwt", DateTime.UtcNow.AddMinutes(10)));

        public Task<TokenValidationParameters> GetValidationParametersAsync(string? audience, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<TokenValidationResult> ValidateAsync(string jwt, string? audience, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<TokenValidationResult> ValidateIgnoringLifetimeAsync(string jwt, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FaultyAudit(IAuditLogRepository inner, Faults faults) : IAuditLogRepository
    {
        public Task AddAsync(AuditLog entry, CancellationToken cancellationToken) =>
            faults.FailAudit ? throw new InvalidOperationException("Simulated audit failure.") : inner.AddAsync(entry, cancellationToken);
    }

    /// <summary>Changes the user's SecurityStamp (as a concurrent password change would) just before the rotation runs.</summary>
    private sealed class StampChangingRefresh(IRefreshTokenService inner, Faults faults, IServiceProvider provider) : IRefreshTokenService
    {
        public async Task<RotationResult> RotateAsync(string rawToken, RefreshContext context, CancellationToken cancellationToken)
        {
            if (faults.ChangeStampDuringRotation is Guid userId)
            {
                await using AsyncServiceScope scope = provider.GetRequiredService<IServiceScopeFactory>().CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<AuthDbContext>().User.Where(u => u.Id == userId)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.SecurityStamp, Guid.NewGuid()), cancellationToken);
            }

            return await inner.RotateAsync(rawToken, context, cancellationToken);
        }

        public Task<IssuedRefreshToken> IssueAsync(Guid userId, Guid? clientApplicationId, RefreshContext context, CancellationToken cancellationToken) =>
            inner.IssueAsync(userId, clientApplicationId, context, cancellationToken);

        public Task<IssuedRefreshToken> IssueAsync(Guid userId, Guid? clientApplicationId, Guid familyId, RefreshContext context, CancellationToken cancellationToken) =>
            inner.IssueAsync(userId, clientApplicationId, familyId, context, cancellationToken);

        public Task<int> RevokeFamilyAsync(Guid familyId, string reason, CancellationToken cancellationToken) => inner.RevokeFamilyAsync(familyId, reason, cancellationToken);

        public Task<int> RevokeFamilyForUserAsync(Guid familyId, Guid userId, string reason, CancellationToken cancellationToken) =>
            inner.RevokeFamilyForUserAsync(familyId, userId, reason, cancellationToken);

        public Task<RefreshSession?> FindSessionAsync(string? rawToken, CancellationToken cancellationToken) => inner.FindSessionAsync(rawToken, cancellationToken);

        public Task<int> RevokeAllAsync(Guid userId, string reason, CancellationToken cancellationToken) => inner.RevokeAllAsync(userId, reason, cancellationToken);
    }
}
