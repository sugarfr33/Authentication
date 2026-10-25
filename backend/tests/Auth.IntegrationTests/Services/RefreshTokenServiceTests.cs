using System.Security.Cryptography;
using System.Text;
using Auth.DAL;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Auth.IntegrationTests.Services;

/// <summary>
/// T08 against the real SQL Express _Test database: the services are built with the public AddAuthServices, with a
/// fake clock and an in-memory log sink.
/// </summary>
public sealed class RefreshTokenServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private static readonly RefreshContext Browser = new("203.0.113.10", "Mozilla/5.0 (Test Browser)");
    private static readonly RefreshContext OtherDevice = new("198.51.100.20", "curl/8.0");

    private readonly TestClock clock = new(TestData.Now);
    private readonly LogSink logs = new();
    private readonly ServiceProvider services;

    public RefreshTokenServiceTests(SqlServerDatabaseFixture database)
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
        collection.AddLogging(logging => logging.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        collection.AddSingleton<IClock>(clock);
        collection.AddAuthServices(configuration);
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private static TimeSpan Grace => TimeSpan.FromSeconds(10);

    [Fact]
    public async Task Issue_stores_only_the_SHA256_hash_with_IP_and_user_agent_and_a_14_day_expiry()
    {
        User user = await SeedUserAsync();

        IssuedRefreshToken issued = await IssueAsync(user.Id, null, Browser);
        RefreshToken row = await LoadByRawAsync(issued.Token);

        Assert.Equal(43, issued.Token.Length);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(issued.Token)), row.TokenHash);
        Assert.Equal(issued.FamilyId, row.FamilyId);
        Assert.Equal(TestData.Now.AddDays(14), row.ExpiresUtc);
        Assert.Equal(Browser.IpAddress, row.IpAddress);
        Assert.Equal(Browser.UserAgent, row.UserAgent);
        Assert.DoesNotContain(issued.Token, RowText(row), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rotation_issues_a_successor_in_the_same_family_and_marks_the_old_row_Rotated()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken first = await IssueAsync(user.Id, null, Browser);
        clock.Advance(TimeSpan.FromMinutes(5));

        RotationResult result = await RotateAsync(first.Token, OtherDevice);

        Assert.Equal(RotationStatus.Rotated, result.Status);
        IssuedRefreshToken next = result.Token!;
        Assert.NotEqual(first.Token, next.Token);
        Assert.Equal(first.FamilyId, next.FamilyId);
        RefreshToken oldRow = await LoadByRawAsync(first.Token);
        RefreshToken newRow = await LoadByRawAsync(next.Token);
        Assert.Equal(clock.UtcNow, oldRow.RevokedUtc);
        Assert.Equal(RefreshTokenRevokedReason.Rotated, oldRow.RevokedReason);
        Assert.Equal(newRow.Id, oldRow.ReplacedByTokenId);
        Assert.Null(newRow.RevokedUtc);
        Assert.Equal(OtherDevice.IpAddress, newRow.IpAddress);
        Assert.Equal(OtherDevice.UserAgent, newRow.UserAgent);
    }

    [Fact]
    public async Task Replaying_a_rotated_token_after_the_grace_window_revokes_the_whole_family()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken first = await IssueAsync(user.Id, null, Browser);
        IssuedRefreshToken otherSession = await IssueAsync(user.Id, null, OtherDevice);
        IssuedRefreshToken second = (await RotateAsync(first.Token, Browser)).Token!;
        clock.Advance(Grace + TimeSpan.FromSeconds(1));

        RotationResult replay = await RotateAsync(first.Token, Browser);

        Assert.Equal(RotationStatus.ReuseDetected, replay.Status);
        Assert.Null(replay.Token);
        Assert.Equal(new TokenReuseDetected(user.Id, first.FamilyId, null, Browser.IpAddress, Browser.UserAgent, 1), replay.Reuse);
        Assert.Equal(RefreshTokenRevokedReason.Reuse, (await LoadByRawAsync(second.Token)).RevokedReason);
        Assert.Equal(RotationStatus.ReuseDetected, (await RotateAsync(second.Token, Browser)).Status);
        Assert.Null((await LoadByRawAsync(otherSession.Token)).RevokedUtc);
    }

    [Fact]
    public async Task Within_the_grace_window_with_the_same_user_agent_the_loser_gets_Concurrent_and_nothing_is_revoked()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken first = await IssueAsync(user.Id, null, Browser);
        IssuedRefreshToken winner = (await RotateAsync(first.Token, Browser)).Token!;
        clock.Advance(Grace);

        RotationResult loser = await RotateAsync(first.Token, Browser);

        Assert.Equal(RotationStatus.Concurrent, loser.Status);
        Assert.Null(loser.Token);
        Assert.Null(loser.Reuse);
        Assert.Null((await LoadByRawAsync(winner.Token)).RevokedUtc);
        Assert.Equal(RotationStatus.Rotated, (await RotateAsync(winner.Token, Browser)).Status);
    }

    /// <summary>Regression (T08 review): the stored user agent is truncated to 512 chars, so the comparison must truncate too.</summary>
    [Fact]
    public async Task A_user_agent_longer_than_the_column_still_gets_Concurrent_inside_the_grace_window()
    {
        RefreshContext longAgent = new("203.0.113.10", "Mozilla/5.0 " + new string('x', 600));
        User user = await SeedUserAsync();
        IssuedRefreshToken first = await IssueAsync(user.Id, null, longAgent);
        IssuedRefreshToken winner = (await RotateAsync(first.Token, longAgent)).Token!;
        clock.Advance(TimeSpan.FromSeconds(3));

        RotationResult loser = await RotateAsync(first.Token, longAgent);

        Assert.Equal(RotationStatus.Concurrent, loser.Status);
        Assert.Equal(512, (await LoadByRawAsync(winner.Token)).UserAgent.Length);
        Assert.Null((await LoadByRawAsync(winner.Token)).RevokedUtc);
    }

    [Fact]
    public async Task Within_the_grace_window_a_different_user_agent_is_treated_as_reuse()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken first = await IssueAsync(user.Id, null, Browser);
        IssuedRefreshToken winner = (await RotateAsync(first.Token, Browser)).Token!;
        clock.Advance(TimeSpan.FromSeconds(2));

        Assert.Equal(RotationStatus.ReuseDetected, (await RotateAsync(first.Token, OtherDevice)).Status);
        Assert.Equal(RefreshTokenRevokedReason.Reuse, (await LoadByRawAsync(winner.Token)).RevokedReason);
    }

    [Fact]
    public async Task A_token_revoked_by_logout_and_replayed_is_reuse()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken issued = await IssueAsync(user.Id, null, Browser);
        await InScopeAsync<IRefreshTokenService, int>(s => s.RevokeFamilyAsync(issued.FamilyId, RefreshTokenRevokedReason.Logout, Ct));

        RotationResult result = await RotateAsync(issued.Token, Browser);

        Assert.Equal(RotationStatus.ReuseDetected, result.Status);
        Assert.Equal(RefreshTokenRevokedReason.Logout, (await LoadByRawAsync(issued.Token)).RevokedReason);
    }

    [Fact]
    public async Task Unknown_and_expired_tokens_get_the_same_Invalid_result()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken issued = await IssueAsync(user.Id, null, Browser);
        clock.Advance(TimeSpan.FromDays(14));

        RotationResult expired = await RotateAsync(issued.Token, Browser);
        RotationResult unknown = await RotateAsync(services.GetRequiredService<ITokenGenerator>().Generate().Value, Browser);
        RotationResult garbage = await RotateAsync(new string('x', 5000), Browser);

        Assert.Equal(new RotationResult(RotationStatus.Invalid, null, null), expired);
        Assert.Equal(new RotationResult(RotationStatus.Invalid, null, null), unknown);
        Assert.Equal(new RotationResult(RotationStatus.Invalid, null, null), garbage);
        Assert.Null((await LoadByRawAsync(issued.Token)).RevokedUtc);
    }

    [Fact]
    public async Task Lifetime_slides_14_days_per_rotation_but_never_past_30_days_from_the_family_start()
    {
        User user = await SeedUserAsync();
        DateTime start = clock.UtcNow;
        IssuedRefreshToken token = await IssueAsync(user.Id, null, Browser);

        clock.Set(start.AddDays(13));
        token = (await RotateAsync(token.Token, Browser)).Token!;
        Assert.Equal(start.AddDays(27), token.ExpiresUtc);

        clock.Set(start.AddDays(26));
        token = (await RotateAsync(token.Token, Browser)).Token!;
        Assert.Equal(start.AddDays(30), token.ExpiresUtc);

        clock.Set(start.AddDays(30));
        Assert.Equal(RotationStatus.Invalid, (await RotateAsync(token.Token, Browser)).Status);
    }

    [Fact]
    public async Task Inactive_user_or_inactive_application_cannot_refresh()
    {
        User inactive = await SeedUserAsync(isActive: false);
        User active = await SeedUserAsync();
        ClientApplication disabledApp = TestData.ClientApplication();
        ClientApplication enabledApp = TestData.ClientApplication();
        await SeedAsync(disabledApp, enabledApp);
        IssuedRefreshToken beforeDeactivation = await IssueAsync(active.Id, disabledApp.Id, Browser);
        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<AuthDbContext>().ClientApplication
                .Where(c => c.Id == disabledApp.Id).ExecuteUpdateAsync(u => u.SetProperty(c => c.IsActive, false));
        }

        Assert.Equal(RotationStatus.Invalid, (await RotateAsync((await IssueAsync(inactive.Id, null, Browser)).Token, Browser)).Status);
        Assert.Equal(RotationStatus.Invalid, (await RotateAsync(beforeDeactivation.Token, Browser)).Status);

        // T18: no family is ever started for an inactive application.
        await Assert.ThrowsAsync<Auth.Services.ClientApplications.InactiveClientApplicationException>(() => IssueAsync(active.Id, disabledApp.Id, Browser));

        RotationResult ok = await RotateAsync((await IssueAsync(active.Id, enabledApp.Id, Browser)).Token, Browser);
        Assert.Equal(RotationStatus.Rotated, ok.Status);
        Assert.Equal(enabledApp.Id, ok.Token!.ClientApplicationId);
    }

    [Fact]
    public async Task Of_two_truly_simultaneous_refreshes_exactly_one_wins()
    {
        User user = await SeedUserAsync();

        for (int round = 0; round < 10; round++)
        {
            IssuedRefreshToken issued = await IssueAsync(user.Id, null, Browser);
            using ManualResetEventSlim gate = new(false);
            Task<RotationResult>[] racers = Enumerable.Range(0, 2).Select(_ => Task.Run(async () =>
            {
                await using AsyncServiceScope scope = services.CreateAsyncScope();
                IRefreshTokenService refresh = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
                gate.Wait();
                return await refresh.RotateAsync(issued.Token, Browser, Ct);
            })).ToArray();
            gate.Set();
            RotationResult[] results = await Task.WhenAll(racers);

            Assert.Equal([RotationStatus.Rotated, RotationStatus.Concurrent], results.Select(r => r.Status).Order());
            List<RefreshToken> family = await LoadFamilyAsync(issued.FamilyId);
            Assert.Equal(2, family.Count);
            Assert.Single(family, t => t.RevokedUtc is null);
            Assert.DoesNotContain(family, t => t.RevokedReason == RefreshTokenRevokedReason.Reuse);
        }
    }

    [Fact]
    public async Task Revoke_family_and_revoke_all_use_the_set_based_updates_and_validate_the_reason()
    {
        User user = await SeedUserAsync();
        IssuedRefreshToken a = await IssueAsync(user.Id, null, Browser);
        IssuedRefreshToken b = await IssueAsync(user.Id, null, OtherDevice);
        IssuedRefreshToken c = await IssueAsync(user.Id, null, OtherDevice);

        Assert.Equal(1, await InScopeAsync<IRefreshTokenService, int>(s => s.RevokeFamilyAsync(a.FamilyId, RefreshTokenRevokedReason.Logout, Ct)));
        Assert.Equal(2, await InScopeAsync<IRefreshTokenService, int>(s => s.RevokeAllAsync(user.Id, RefreshTokenRevokedReason.LogoutAll, Ct)));
        await Assert.ThrowsAsync<ArgumentException>(() => InScopeAsync<IRefreshTokenService, int>(s => s.RevokeAllAsync(user.Id, "Whatever", Ct)));

        Assert.Equal(RefreshTokenRevokedReason.Logout, (await LoadByRawAsync(a.Token)).RevokedReason);
        Assert.Equal(RefreshTokenRevokedReason.LogoutAll, (await LoadByRawAsync(b.Token)).RevokedReason);
        Assert.Equal(RefreshTokenRevokedReason.LogoutAll, (await LoadByRawAsync(c.Token)).RevokedReason);
    }

    [Fact]
    public async Task Raw_tokens_never_reach_logs_exceptions_or_stored_rows()
    {
        User user = await SeedUserAsync();
        List<string> raws = [];
        List<string> texts = [];

        IssuedRefreshToken issued = await IssueAsync(user.Id, null, Browser);
        raws.Add(issued.Token);
        IssuedRefreshToken rotated = (await RotateAsync(issued.Token, Browser)).Token!;
        raws.Add(rotated.Token);
        clock.Advance(TimeSpan.FromMinutes(1));
        await RotateAsync(issued.Token, Browser);
        await RotateAsync(issued.Token + "tampered", Browser);
        try
        {
            await InScopeAsync<IRefreshTokenService, int>(s => s.RevokeFamilyAsync(issued.FamilyId, issued.Token, Ct));
        }
        catch (ArgumentException ex)
        {
            texts.Add(ex.ToString());
        }

        texts.AddRange(logs.Messages);
        texts.AddRange((await LoadFamilyAsync(issued.FamilyId)).Select(RowText));
        Assert.NotEmpty(texts);
        Assert.All(raws, raw => Assert.All(texts, text => Assert.DoesNotContain(raw, text, StringComparison.Ordinal)));
    }

    public async ValueTask DisposeAsync()
    {
        await services.DisposeAsync();
        logs.Dispose();
    }

    private async Task<User> SeedUserAsync(bool isActive = true)
    {
        User user = TestData.User();
        user.IsActive = isActive;
        await SeedAsync(user);
        return user;
    }

    private async Task<IssuedRefreshToken> IssueAsync(Guid userId, Guid? clientApplicationId, RefreshContext context)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IRefreshTokenService>().IssueAsync(userId, clientApplicationId, context, Ct);
    }

    private async Task<RotationResult> RotateAsync(string raw, RefreshContext context)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IRefreshTokenService>().RotateAsync(raw, context, Ct);
    }

    private new async Task<TResult> InScopeAsync<TService, TResult>(Func<TService, Task<TResult>> action)
        where TService : notnull
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    private async Task<RefreshToken> LoadByRawAsync(string raw)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AuthDbContext>().RefreshToken.AsNoTracking().SingleAsync(t => t.TokenHash == hash, Ct);
    }

    private async Task<List<RefreshToken>> LoadFamilyAsync(Guid familyId)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AuthDbContext>().RefreshToken.AsNoTracking().Where(t => t.FamilyId == familyId).ToListAsync(Ct);
    }

    /// <summary>Every column of a row as text, to prove the raw token is not stored anywhere.</summary>
    private static string RowText(RefreshToken row) => string.Join(
        "|",
        row.Id, row.UserId, row.ClientApplicationId, row.FamilyId, Convert.ToBase64String(row.TokenHash), Convert.ToHexString(row.TokenHash),
        row.CreatedUtc, row.ExpiresUtc, row.RevokedUtc, row.RevokedReason, row.ReplacedByTokenId, row.IpAddress, row.UserAgent);

    private sealed class TestClock(DateTime start) : IClock
    {
        private long ticks = start.Ticks;

        public DateTime UtcNow => new(Interlocked.Read(ref ticks), DateTimeKind.Utc);

        public void Advance(TimeSpan by) => Interlocked.Add(ref ticks, by.Ticks);

        public void Set(DateTime utc) => Interlocked.Exchange(ref ticks, utc.Ticks);
    }

    private sealed class LogSink : ILoggerProvider
    {
        private readonly List<string> messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (messages)
                {
                    return [.. messages];
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new Logger(this);

        public void Dispose()
        {
        }

        private sealed class Logger(LogSink owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (owner.messages)
                {
                    owner.messages.Add(formatter(state, exception) + " " + exception);
                }
            }
        }
    }
}
