using Auth.Contracts;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.IntegrationTests.DAL;
using Auth.Services;
using Auth.Services.Accounts;
using Auth.Services.Common;
using Auth.Services.Retention;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Services;

/// <summary>
/// T17 retention purge against SQL Express. Each test works in its own past year, so rows of other tests in the shared
/// database are never in range of its cutoffs.
/// </summary>
public sealed class RetentionPurgeTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public async Task Refresh_families_are_deleted_only_whole_and_only_when_every_token_ended_before_the_cutoff()
    {
        DateTime cutoff = Utc(2000, 6, 1);
        User user = await UserAsync();
        Guid ended = Guid.NewGuid();
        RefreshToken rotated = Token(user.Id, ended, Utc(2000, 1, 1), Utc(2000, 1, 15), revokedUtc: Utc(2000, 1, 2));
        RefreshToken last = Token(user.Id, ended, Utc(2000, 1, 2), Utc(2000, 1, 16));
        rotated.ReplacedByTokenId = last.Id;
        Guid endedAfterCutoff = Guid.NewGuid();
        RefreshToken oldPart = Token(user.Id, endedAfterCutoff, Utc(2000, 1, 1), Utc(2000, 1, 15), revokedUtc: Utc(2000, 1, 2));
        RefreshToken recentPart = Token(user.Id, endedAfterCutoff, Utc(2000, 1, 2), Utc(2000, 12, 31));
        Guid live = Guid.NewGuid();
        RefreshToken liveOld = Token(user.Id, live, Utc(2000, 1, 1), Utc(2000, 1, 15), revokedUtc: Utc(2000, 1, 2));
        RefreshToken liveNow = Token(user.Id, live, Utc(2000, 1, 2), DateTime.UtcNow.AddDays(1));
        await SeedAsync(last, rotated, oldPart, recentPart, liveOld, liveNow);

        int deleted = await RepositoryAsync(r => r.DeleteEndedRefreshFamiliesAsync(cutoff, 1000, Ct));

        Assert.Equal(2, deleted);
        Assert.Empty(await FamilyAsync(ended));
        Assert.Equal(2, (await FamilyAsync(endedAfterCutoff)).Count);
        Assert.Equal(2, (await FamilyAsync(live)).Count);
    }

    /// <summary>Review MEDIUM-1: a statement deletes at most a batch of ROWS, even of one long family.</summary>
    [Fact]
    public async Task A_long_family_is_removed_over_several_row_bounded_statements_and_nothing_else_is_touched()
    {
        User user = await UserAsync();
        Guid longFamily = Guid.NewGuid();
        List<RefreshToken> chain = [.. Enumerable.Range(0, 25).Select(i => Token(user.Id, longFamily, Utc(2001, 1, 1).AddMinutes(i), Utc(2001, 1, 15), revokedUtc: Utc(2001, 1, 1).AddMinutes(i + 1)))];
        for (int i = 0; i < chain.Count - 1; i++)
        {
            chain[i].ReplacedByTokenId = chain[i + 1].Id;
        }

        Guid lateFamily = Guid.NewGuid();
        Guid liveFamily = Guid.NewGuid();
        await SeedAsync([.. Enumerable.Reverse(chain)]);
        await SeedAsync(
            Token(user.Id, lateFamily, Utc(2001, 1, 1), Utc(2001, 12, 31)),
            Token(user.Id, liveFamily, Utc(2001, 1, 1), DateTime.UtcNow.AddDays(1)));
        RetentionOptions options = new() { RefreshTokenBatchSize = 10, MaxBatchesPerRun = 1 };
        DateTime now = Utc(2001, 7, 1);

        await PurgeAsync(options, now);
        int afterOneRun = (await FamilyAsync(longFamily)).Count;
        for (int run = 0; run < 10 && (await FamilyAsync(longFamily)).Count > 0; run++)
        {
            await PurgeAsync(options, now);
        }

        Assert.InRange(25 - afterOneRun, 1, 10);
        Assert.Empty(await FamilyAsync(longFamily));
        Assert.Single(await FamilyAsync(lateFamily));
        Assert.Single(await FamilyAsync(liveFamily));
    }

    /// <summary>Review LOW-4: rows of event types that no longer exist follow the normal retention.</summary>
    [Fact]
    public async Task Audit_rows_of_unknown_event_types_are_purged_after_the_normal_retention()
    {
        User user = await UserAsync();
        AuditLog legacy = TestData.AuditLog(user.Id);
        (legacy.EventType, legacy.OccurredUtc) = ("LegacyRemovedEvent", Utc(2004, 1, 1));
        await SeedAsync(legacy);

        await PurgeAsync(new RetentionOptions(), Utc(2004, 6, 1));
        bool keptWithinRetention = await WithContextAsync(c => c.AuditLog.AnyAsync(a => a.Id == legacy.Id));
        await PurgeAsync(new RetentionOptions(), Utc(2005, 1, 2));

        Assert.True(keptWithinRetention);
        Assert.False(await WithContextAsync(c => c.AuditLog.AnyAsync(a => a.Id == legacy.Id)));
    }

    [Fact]
    public async Task High_volume_audit_rows_get_the_shorter_retention_and_runs_are_bounded()
    {
        User user = await UserAsync();
        DateTime occurred = Utc(2002, 1, 1);
        await SeedAsync([.. Enumerable.Range(0, 3).SelectMany(_ => new object[] { Audit(user.Id, AuditEventType.LoginFailed, occurred), Audit(user.Id, AuditEventType.LoginSucceeded, occurred) })]);
        RetentionOptions options = new() { BatchSize = 2, MaxBatchesPerRun = 1, HighVolumeAuditLog = TimeSpan.FromDays(90), AuditLog = TimeSpan.FromDays(365) };
        DateTime now = occurred.AddDays(100);

        await PurgeAsync(options, now);
        int failedAfterOneRun = await AuditCountAsync(user.Id, AuditEventType.LoginFailed);
        await PurgeAsync(options, now);

        Assert.Equal(1, failedAfterOneRun);
        Assert.Equal(0, await AuditCountAsync(user.Id, AuditEventType.LoginFailed));
        Assert.Equal(3, await AuditCountAsync(user.Id, AuditEventType.LoginSucceeded));

        await PurgeAsync(new RetentionOptions(), occurred.AddDays(366));
        Assert.Equal(0, await AuditCountAsync(user.Id, AuditEventType.LoginSucceeded));
    }

    [Fact]
    public async Task Expired_links_lose_their_pending_password_at_once_and_are_deleted_after_retention()
    {
        User user = await UserAsync();
        EmailVerificationToken expired = TestData.EmailVerificationToken(user.Id);
        (expired.CreatedUtc, expired.ExpiresUtc, expired.PendingPasswordHash, expired.PendingDisplayName) = (Utc(2003, 1, 1), Utc(2003, 1, 2), "$argon2id$pending", "Pending Name");
        EmailVerificationToken current = TestData.EmailVerificationToken(user.Id);
        (current.CreatedUtc, current.ExpiresUtc, current.PendingPasswordHash) = (Utc(2003, 1, 2), Utc(2003, 1, 4), "$argon2id$current");
        PasswordResetToken usedReset = TestData.PasswordResetToken(user.Id);
        (usedReset.CreatedUtc, usedReset.ExpiresUtc, usedReset.UsedUtc) = (Utc(2003, 1, 1), Utc(2003, 1, 1, 15), Utc(2003, 1, 1, 5));
        await SeedAsync(expired, current, usedReset);

        await PurgeAsync(new RetentionOptions(), Utc(2003, 1, 3));
        EmailVerificationToken erased = await WithContextAsync(c => c.EmailVerificationToken.AsNoTracking().SingleAsync(t => t.Id == expired.Id));
        EmailVerificationToken untouched = await WithContextAsync(c => c.EmailVerificationToken.AsNoTracking().SingleAsync(t => t.Id == current.Id));

        Assert.Equal((null, null), (erased.PendingPasswordHash, erased.PendingDisplayName));
        Assert.Equal("$argon2id$current", untouched.PendingPasswordHash);
        Assert.True(await WithContextAsync(c => c.PasswordResetToken.AnyAsync(t => t.Id == usedReset.Id)));

        await PurgeAsync(new RetentionOptions(), Utc(2003, 1, 10));

        Assert.False(await WithContextAsync(c => c.EmailVerificationToken.AnyAsync(t => t.Id == expired.Id)));
        Assert.False(await WithContextAsync(c => c.PasswordResetToken.AnyAsync(t => t.Id == usedReset.Id)));
        Assert.True(await WithContextAsync(c => c.EmailVerificationToken.AnyAsync(t => t.Id == current.Id)));
    }

    [Fact]
    public void Retention_settings_that_would_purge_too_eagerly_are_refused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetentionOptions { HighVolumeAuditLog = TimeSpan.FromDays(1) }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetentionOptions { AuditLog = TimeSpan.FromDays(60) }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetentionOptions { AuditLog = TimeSpan.FromDays(29), HighVolumeAuditLog = TimeSpan.FromDays(7) }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetentionOptions { BatchSize = 0 }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetentionOptions { BatchSize = 4001 }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetentionOptions { RefreshTokenBatchSize = 4001 }.Validated());
        new RetentionOptions { AuditLog = TimeSpan.FromDays(30), HighVolumeAuditLog = TimeSpan.FromDays(7), BatchSize = 4000 }.Validated();
        Assert.False(new RetentionOptions().Validated().Enabled);
    }

    private static DateTime Utc(int year, int month, int day, int hour = 0) => new(year, month, day, hour, 0, 0, DateTimeKind.Utc);

    private static RefreshToken Token(Guid userId, Guid family, DateTime createdUtc, DateTime expiresUtc, DateTime? revokedUtc = null)
    {
        RefreshToken token = TestData.RefreshToken(userId, family, expiresUtc, createdUtc);
        token.RevokedUtc = revokedUtc;
        token.RevokedReason = revokedUtc is null ? null : RefreshTokenRevokedReason.Rotated;
        return token;
    }

    private static AuditLog Audit(Guid userId, AuditEventType type, DateTime occurredUtc)
    {
        AuditLog row = TestData.AuditLog(userId);
        row.EventType = type.ToString();
        row.OccurredUtc = occurredUtc;
        return row;
    }

    private async Task<User> UserAsync()
    {
        User user = TestData.User();
        await SeedAsync(user);
        return user;
    }

    private Task<List<RefreshToken>> FamilyAsync(Guid family) =>
        WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.FamilyId == family).ToListAsync());

    private Task<int> AuditCountAsync(Guid userId, AuditEventType type)
    {
        string name = type.ToString();
        return WithContextAsync(c => c.AuditLog.CountAsync(a => a.UserId == userId && a.EventType == name));
    }

    private async Task PurgeAsync(RetentionOptions options, DateTime now)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CentralAuth"] = Database.ConnectionString,
                ["Auth:Issuer"] = "https://auth.example.test",
            })
            .Build();
        ServiceCollection collection = new();
        collection.AddSingleton<IClock>(new FixedClock(now));
        collection.AddSingleton(options);
        collection.AddSingleton<IEmailSender>(new CapturingEmailSender());
        collection.AddAuthServices(configuration);
        await using ServiceProvider services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IRetentionPurge>().PurgeAsync(Ct);
    }

    private async Task<T> RepositoryAsync<T>(Func<IRetentionRepository, Task<T>> action)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<IRetentionRepository>());
    }

    private async Task<T> WithContextAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private sealed class FixedClock(DateTime now) : IClock
    {
        public DateTime UtcNow => now;
    }
}
