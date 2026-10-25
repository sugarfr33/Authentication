using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Accounts;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Auth.Services.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests.Services;

/// <summary>T13 sign-in against SQL Express: the same hashing work on every path (counted), lockout and sessions.</summary>
public sealed class SignInServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private const string Password = "violet-canyon-7319";

    private readonly ServiceProvider services;
    private readonly CountingHasher hasher;
    private readonly RecordingTokenService tokens = new();

    public SignInServiceTests(SqlServerDatabaseFixture database)
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
        collection.AddSingleton(new RefreshTokenOptions { MaxSessionsPerUser = 3 });
        collection.AddAuthServices(configuration);
        collection.AddSingleton<ITokenService>(tokens);
        ServiceDescriptor real = collection.Last(d => d.ServiceType == typeof(IPasswordHasher));
        CountingHasher? created = null;
        collection.AddSingleton<IPasswordHasher>(sp => created = new CountingHasher((IPasswordHasher)real.ImplementationFactory!(sp)));
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        services.GetRequiredService<IPasswordHasher>();
        hasher = created!;
    }

    [Fact]
    public async Task Every_failure_path_costs_exactly_one_Verify_and_no_Hash()
    {
        string good = await SeedAsync();
        string unverified = await SeedAsync(verified: false);
        string inactive = await SeedAsync(active: false);
        string locked = await SeedAsync(lockedUntil: TestData.Now.AddYears(50));
        string noPassword = await SeedAsync(hash: string.Empty);
        string mfa = await SeedAsync(mfa: true);
        await services.GetRequiredService<IAuthTimingGuard>().WarmUpAsync(Ct);

        (string Email, string Password)[] failures =
        [
            (good, "wrong-password-0000"),
            ("nobody-" + Guid.NewGuid().ToString("N")[..8] + "@example.test", Password),
            (unverified, Password),
            (inactive, Password),
            (locked, Password),
            (noPassword, Password),
            (mfa, Password),
        ];

        foreach ((string email, string password) in failures)
        {
            hasher.Reset();
            Result<SignedIn> result = await LoginAsync(email, password);

            Assert.Equal(AuthError.GenericInvalidCredentials, result.Error);
            Assert.Equal((1, 0), (hasher.VerifyCalls, hasher.HashCalls));
        }

        hasher.Reset();
        Assert.True((await LoginAsync(good, Password)).IsSuccess);
        Assert.Equal((1, 0), (hasher.VerifyCalls, hasher.HashCalls));
    }

    [Fact]
    public async Task Passwords_over_128_code_points_are_refused_before_any_Verify()
    {
        string good = await SeedAsync();
        hasher.Reset();

        Result<SignedIn> result = await LoginAsync(good, new string('p', 129));

        Assert.Equal(AuthError.GenericInvalidCredentials, result.Error);
        Assert.Equal(0, hasher.VerifyCalls);
    }

    [Fact]
    public async Task Success_starts_a_session_for_the_default_audience_and_resets_the_failure_count()
    {
        string email = await SeedAsync();
        await LoginAsync(email, "wrong-password-1");
        await LoginAsync(email, "wrong-password-2");
        Assert.Equal(2, (await LoadAsync(email)).FailedLoginCount);

        Result<SignedIn> result = await LoginAsync(email, Password);

        SignedIn session = Assert.IsType<SignedIn>(result.Value);
        User user = await LoadAsync(email);
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Equal(user.Id, session.RefreshToken.UserId);
        Assert.Null(session.RefreshToken.ClientApplicationId);
        Assert.Equal(email, session.Profile.Email);
        AccessTokenRequest minted = Assert.Single(tokens.Requests);
        Assert.Equal(services.GetRequiredService<TokenOptions>().DefaultAudience, minted.Audience);
        Assert.Null(minted.ClientId);
        Assert.Equal(session.RefreshToken.FamilyId, minted.SessionId);
        Assert.Equal((user.Id, email), (minted.UserId, minted.Email));
    }

    /// <summary>T15 review: a login beyond MaxSessionsPerUser (3 here) ends the least recently used session first.</summary>
    [Fact]
    public async Task A_login_over_the_session_cap_ends_the_least_recently_used_session()
    {
        string email = await SeedAsync();
        List<Guid> families = [];
        for (int i = 0; i < 4; i++)
        {
            families.Add((await LoginAsync(email, Password)).Value!.RefreshToken.FamilyId);
        }

        Guid userId = (await LoadAsync(email)).Id;
        IReadOnlyList<SessionResponse> live = await InScopeAsync(s => s.ListSessionsAsync(userId, null, 50, Ct));

        Assert.Equal(families.Skip(1).Order(), live.Select(l => l.FamilyId).Order());
        await using AsyncServiceScope scope = Database.CreateScope();
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.All(await context.RefreshToken.AsNoTracking().Where(t => t.FamilyId == families[0]).ToListAsync(), t => Assert.Equal(RefreshTokenRevokedReason.Admin, t.RevokedReason));
        AuditLog audit = Assert.Single(await context.AuditLog.AsNoTracking().Where(a => a.UserId == userId && a.EventType == "SessionRevoked").ToListAsync());
        Assert.Equal("{\"session\":\"" + families[0].ToString("D") + "\",\"reason\":\"session_cap\"}", audit.Detail);
    }

    [Fact]
    public async Task Profile_is_not_found_for_an_inactive_or_unknown_user()
    {
        string inactive = await SeedAsync(active: false);
        Guid inactiveId = (await LoadAsync(inactive)).Id;

        Result<UserProfileResponse> profile = await InScopeAsync(s => s.GetProfileAsync(inactiveId, Ct));
        Result<UserProfileResponse> unknown = await InScopeAsync(s => s.GetProfileAsync(Guid.NewGuid(), Ct));

        Assert.Equal(AuthError.NotFound, profile.Error);
        Assert.Equal(AuthError.NotFound, unknown.Error);
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private Task<Result<SignedIn>> LoginAsync(string email, string password) =>
        InScopeAsync(s => s.LoginAsync(new LoginRequest(email, password, null), null, new AuditContext("203.0.113.5", "tests", null), Ct));

    private async Task<T> InScopeAsync<T>(Func<ISignInService, Task<T>> action)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<ISignInService>());
    }

    private async Task<string> SeedAsync(bool verified = true, bool active = true, DateTime? lockedUntil = null, string? hash = null, bool mfa = false)
    {
        string email = "signin-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        DateTime now = DateTime.UtcNow;
        await SeedAsync(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = verified,
            PasswordHash = hash ?? await hasher.HashAsync(Password, Ct),
            DisplayName = "Sign-in Tester",
            IsActive = active,
            LockoutEndUtc = lockedUntil,
            MfaEnabled = mfa,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        });
        return email;
    }

    private async Task<User> LoadAsync(string email)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AuthDbContext>().User.AsNoTracking()
            .SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email));
    }

    /// <summary>Records what the sign-in asks to mint; signing itself is covered by the token and API tests.</summary>
    private sealed class RecordingTokenService : ITokenService
    {
        public List<AccessTokenRequest> Requests { get; } = [];

        public Task<AccessToken> CreateAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(new AccessToken("test-jwt", DateTime.UtcNow.AddMinutes(10)));
        }

        public Task<TokenValidationParameters> GetValidationParametersAsync(string? audience, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<TokenValidationResult> ValidateAsync(string jwt, string? audience, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<TokenValidationResult> ValidateIgnoringLifetimeAsync(string jwt, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class CountingHasher(IPasswordHasher inner) : IPasswordHasher
    {
        private int hashCalls;
        private int verifyCalls;

        public int HashCalls => Volatile.Read(ref hashCalls);

        public int VerifyCalls => Volatile.Read(ref verifyCalls);

        public void Reset() => (hashCalls, verifyCalls) = (0, 0);

        public string Hash(string password) => throw new InvalidOperationException("Request paths must use HashAsync.");

        public PasswordVerifyResult Verify(string password, string storedHash) => throw new InvalidOperationException("Request paths must use VerifyAsync.");

        public Task<string> HashAsync(string password, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref hashCalls);
            return inner.HashAsync(password, cancellationToken);
        }

        public Task<PasswordVerifyResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref verifyCalls);
            return inner.VerifyAsync(password, storedHash, cancellationToken);
        }
    }
}
