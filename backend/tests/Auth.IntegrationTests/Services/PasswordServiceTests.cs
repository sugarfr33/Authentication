using System.Security.Cryptography;
using System.Text;
using Auth.Contracts;
using Auth.Contracts.Requests;
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

namespace Auth.IntegrationTests.Services;

/// <summary>T14 forgot, reset and change password against SQL Express, with a fake clock and a captured mailbox.</summary>
public sealed class PasswordServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private const string OldPassword = "violet-canyon-7319";
    private const string NewPassword = "amber-harbor-5826";

    private readonly MutableClock clock = new(DateTime.UtcNow);
    private readonly CapturingEmailSender mailbox = new();
    private readonly ServiceProvider services;

    public PasswordServiceTests(SqlServerDatabaseFixture database)
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
        collection.AddSingleton<IClock>(clock);
        collection.AddSingleton(new PasswordHashingOptions { MemorySizeKiB = 1024, Iterations = 1, Parallelism = 1 });
        collection.AddSingleton(new AccountEmailOptions { ResetPasswordUrl = new Uri("https://app.example.test/reset-password") });
        collection.AddSingleton<IEmailSender>(mailbox);
        collection.AddAuthServices(configuration);
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    [Fact]
    public async Task Forgot_password_for_a_verified_account_stores_only_the_hash_of_a_15_minute_link()
    {
        string email = await SeedAsync();

        PasswordResult result = await ForgotAsync(email);

        Assert.True(result.IsSuccess);
        EmailMessage message = mailbox.OnlyTo(email);
        Assert.Contains("https://app.example.test/reset-password#token=", message.Body, StringComparison.Ordinal);
        string token = TokenFrom(message);
        PasswordResetToken row = Assert.Single(await ResetLinksAsync(email));
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(token)), row.TokenHash);
        Assert.Equal(TimeSpan.FromMinutes(15), row.ExpiresUtc - row.CreatedUtc);
        Assert.Equal("203.0.113.9", row.RequestIp);
    }

    [Fact]
    public async Task Forgot_password_does_the_same_work_for_every_kind_of_email()
    {
        string verified = await SeedAsync();
        string unverified = await SeedAsync(verified: false, hash: string.Empty);
        string inactive = await SeedAsync(active: false);
        string unknown = "nobody-" + Guid.NewGuid().ToString("N")[..8] + "@example.test";

        foreach (string email in new[] { verified, unverified, inactive, unknown })
        {
            int mailsBefore = mailbox.Messages.Count;
            string correlation = "forgot-" + Guid.NewGuid().ToString("N")[..8];

            PasswordResult result = await InScopeAsync(s => s.ForgotPasswordAsync(new ForgotPasswordRequest(email), new AuditContext("203.0.113.9", "tests", correlation), Ct));

            Assert.Same(PasswordResult.Ok, result);
            Assert.Equal(1, mailbox.Messages.Count - mailsBefore);
            Assert.Single(await WithContextAsync(c => c.AuditLog.AsNoTracking().Where(a => a.CorrelationId == correlation).ToListAsync()));
        }

        Assert.Contains("#token=", mailbox.OnlyTo(verified).Body, StringComparison.Ordinal);
        Assert.All(new[] { unverified, inactive, unknown }, e => Assert.DoesNotContain("#token=", mailbox.OnlyTo(e).Body, StringComparison.Ordinal));
        Assert.Empty(await ResetLinksAsync(unverified));
        Assert.Empty(await ResetLinksAsync(inactive));
    }

    [Fact]
    public async Task Reset_sets_the_new_password_and_ends_everything_the_old_one_allowed()
    {
        string email = await SeedAsync();
        Guid userId = (await LoadAsync(email)).Id;
        await WithContextAsync(c => c.User.Where(u => u.Id == userId).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.FailedLoginCount, 3).SetProperty(u => u.LockoutLevel, 2).SetProperty(u => u.LockoutEndUtc, clock.UtcNow.AddMinutes(5))));
        await IssueSessionAsync(userId);
        await IssueSessionAsync(userId);
        Guid stampBefore = (await LoadAsync(email)).SecurityStamp;
        await ForgotAsync(email);
        await ForgotAsync(email);

        PasswordResult result = await ResetAsync(TokenFrom(mailbox.To(email)[0]), NewPassword);

        Assert.True(result.IsSuccess);
        User user = await LoadAsync(email);
        Assert.NotEqual(stampBefore, user.SecurityStamp);
        Assert.Equal((0, 0, (DateTime?)null), (user.FailedLoginCount, user.LockoutLevel, user.LockoutEndUtc));
        Assert.True(user.EmailVerified);
        Assert.True(await PasswordWorksAsync(user, NewPassword));
        Assert.False(await PasswordWorksAsync(user, OldPassword));
        Assert.All(await WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync()),
            t => Assert.Equal(RefreshTokenRevokedReason.PasswordChange, t.RevokedReason));
        Assert.All(await ResetLinksAsync(email), l => Assert.NotNull(l.UsedUtc));
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(TokenFrom(mailbox.To(email)[1]), "another-password-1234")).Error);
        Assert.Contains("Your password was changed", mailbox.To(email)[^1].Subject, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reset_links_are_single_use_expire_and_reject_unknown_or_tampered_values()
    {
        string email = await SeedAsync();
        await ForgotAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));
        string tampered = (token[0] == 'A' ? "B" : "A") + token[1..];

        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(tampered, NewPassword)).Error);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync("not-a-token", NewPassword)).Error);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(string.Empty, NewPassword)).Error);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(new string('a', 300), NewPassword)).Error);
        Assert.True((await ResetAsync(token, NewPassword)).IsSuccess);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(token, "third-password-7777")).Error);

        mailbox.Clear();
        await ForgotAsync(email);
        string late = TokenFrom(mailbox.OnlyTo(email));
        clock.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(late, "fourth-password-8888")).Error);
        Assert.True(await PasswordWorksAsync(await LoadAsync(email), NewPassword));
    }

    [Fact]
    public async Task A_rejected_new_password_is_a_validation_error_and_leaves_the_link_usable()
    {
        string email = await SeedAsync();
        await ForgotAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));
        string localPart = email[..email.IndexOf('@', StringComparison.Ordinal)];

        PasswordResult tooShort = await ResetAsync(token, "short");
        PasswordResult common = await ResetAsync(token, "password1234");
        PasswordResult matchesEmail = await ResetAsync(token, localPart);

        Assert.All([tooShort, common, matchesEmail], r =>
        {
            Assert.Equal(AuthError.ValidationFailed, r.Error);
            Assert.True(r.ValidationErrors!.ContainsKey("newPassword"));
        });
        Assert.True((await ResetAsync(token, NewPassword)).IsSuccess);
    }

    [Fact]
    public async Task Concurrent_resets_with_one_link_succeed_exactly_once()
    {
        string email = await SeedAsync();
        await ForgotAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));

        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<PasswordResult>[] racers = [.. Enumerable.Range(0, 16).Select(i => Task.Run(async () =>
        {
            await start.Task;
            return await ResetAsync(token, "racing-password-" + i.ToString("D4", System.Globalization.CultureInfo.InvariantCulture));
        }))];
        start.SetResult();
        PasswordResult[] results = await Task.WhenAll(racers);

        Assert.Equal(1, results.Count(r => r.IsSuccess));
        Assert.All(results.Where(r => !r.IsSuccess), r => Assert.Equal(AuthError.InvalidOrExpiredToken, r.Error));
    }

    [Fact]
    public async Task Reset_never_marks_an_unverified_account_verified_and_clears_pending_sign_up_passwords()
    {
        string email = await SeedAsync(verified: false, hash: string.Empty);
        Guid userId = (await LoadAsync(email)).Id;
        GeneratedToken planted = services.GetRequiredService<ITokenGenerator>().Generate();
        await SeedAsync(
            new PasswordResetToken { UserId = userId, TokenHash = planted.Hash, CreatedUtc = clock.UtcNow, ExpiresUtc = clock.UtcNow.AddMinutes(15), RequestIp = "x" },
            new EmailVerificationToken
            {
                UserId = userId, TokenHash = RandomNumberGenerator.GetBytes(32), CreatedUtc = clock.UtcNow, ExpiresUtc = clock.UtcNow.AddHours(1),
                PendingPasswordHash = "$argon2id$pending", PendingDisplayName = "Pending",
            });

        Assert.True((await ResetAsync(planted.Value, NewPassword)).IsSuccess);

        Assert.False((await LoadAsync(email)).EmailVerified);
        EmailVerificationToken link = Assert.Single(await WithContextAsync(c => c.EmailVerificationToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync()));
        Assert.Equal((null, null), (link.PendingPasswordHash, link.PendingDisplayName));
        Assert.NotNull(link.UsedUtc);
    }

    [Fact]
    public async Task Change_password_needs_the_current_one_and_counts_wrong_attempts_toward_lockout()
    {
        string email = await SeedAsync();
        Guid userId = (await LoadAsync(email)).Id;

        PasswordResult wrong = await ChangeAsync(userId, "not-the-password-1", NewPassword);
        PasswordResult policy = await ChangeAsync(userId, OldPassword, "short");

        Assert.Equal(AuthError.GenericInvalidCredentials, wrong.Error);
        Assert.Equal(AuthError.ValidationFailed, policy.Error);
        User user = await LoadAsync(email);
        Assert.Equal(1, user.FailedLoginCount);
        Assert.True(await PasswordWorksAsync(user, OldPassword));
    }

    [Fact]
    public async Task Change_password_replaces_the_password_and_revokes_every_session()
    {
        string email = await SeedAsync();
        Guid userId = (await LoadAsync(email)).Id;
        await IssueSessionAsync(userId);
        await IssueSessionAsync(userId);

        PasswordResult result = await ChangeAsync(userId, OldPassword, NewPassword);

        Assert.True(result.IsSuccess);
        User user = await LoadAsync(email);
        Assert.True(await PasswordWorksAsync(user, NewPassword));
        Assert.False(await PasswordWorksAsync(user, OldPassword));
        List<RefreshToken> sessions = await WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync());
        Assert.Equal(2, sessions.Count);
        Assert.All(sessions, t => Assert.Equal(RefreshTokenRevokedReason.PasswordChange, t.RevokedReason));
        Assert.Contains(await WithContextAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync()), a => a.EventType == nameof(AuditEventType.PasswordChanged));
    }

    /// <summary>Review T14: the post-commit notice is best effort; a failing sender never turns a done change into an error.</summary>
    [Fact]
    public async Task A_failing_notice_email_does_not_undo_or_fail_a_reset()
    {
        string email = await SeedAsync();
        Guid userId = (await LoadAsync(email)).Id;
        await IssueSessionAsync(userId);
        await ForgotAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));
        mailbox.FailWhen = m => m.Subject == "Your password was changed";

        PasswordResult result = await ResetAsync(token, NewPassword);

        Assert.True(result.IsSuccess);
        Assert.Equal(nameof(InvalidOperationException), result.NoticeFailure);
        Assert.True(await PasswordWorksAsync(await LoadAsync(email), NewPassword));
        Assert.Equal(RefreshTokenRevokedReason.PasswordChange, Assert.Single(await WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync())).RevokedReason);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await ResetAsync(token, "another-password-1234")).Error);
    }

    [Fact]
    public async Task A_failing_notice_email_does_not_undo_or_fail_a_change()
    {
        string email = await SeedAsync();
        Guid userId = (await LoadAsync(email)).Id;
        await IssueSessionAsync(userId);
        mailbox.FailWhen = m => m.Subject == "Your password was changed";

        PasswordResult result = await ChangeAsync(userId, OldPassword, NewPassword);

        Assert.True(result.IsSuccess);
        Assert.Equal(nameof(InvalidOperationException), result.NoticeFailure);
        Assert.True(await PasswordWorksAsync(await LoadAsync(email), NewPassword));
        Assert.Equal(RefreshTokenRevokedReason.PasswordChange, Assert.Single(await WithContextAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync())).RevokedReason);
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private static string TokenFrom(EmailMessage message)
    {
        const string marker = "#token=";
        int start = message.Body.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The email holds no link.");
        return new string(message.Body[(start + marker.Length)..].TakeWhile(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray());
    }

    private Task<PasswordResult> ForgotAsync(string email) =>
        InScopeAsync(s => s.ForgotPasswordAsync(new ForgotPasswordRequest(email), new AuditContext("203.0.113.9", "tests", null), Ct));

    private Task<PasswordResult> ResetAsync(string token, string password) =>
        InScopeAsync(s => s.ResetPasswordAsync(new ResetPasswordRequest(token, password), AuditContext.None, Ct));

    private Task<PasswordResult> ChangeAsync(Guid userId, string current, string next) =>
        InScopeAsync(s => s.ChangePasswordAsync(userId, new ChangePasswordRequest(current, next), AuditContext.None, Ct));

    private async Task<T> InScopeAsync<T>(Func<IPasswordService, Task<T>> action)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<IPasswordService>());
    }

    private async Task IssueSessionAsync(Guid userId)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IRefreshTokenService>().IssueAsync(userId, null, new RefreshContext("203.0.113.9", "tests"), Ct);
    }

    private async Task<bool> PasswordWorksAsync(User user, string password) =>
        await services.GetRequiredService<IAuthTimingGuard>().CheckPasswordAsync(password, user.PasswordHash, accountUsable: true, Ct) is CredentialCheck.Valid or CredentialCheck.ValidNeedsRehash;

    private async Task<string> SeedAsync(bool verified = true, bool active = true, string? hash = null)
    {
        string email = "pwd-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        DateTime now = clock.UtcNow;
        await SeedAsync(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = verified,
            PasswordHash = hash ?? await services.GetRequiredService<IPasswordHasher>().HashAsync(OldPassword, Ct),
            DisplayName = "Password Tester",
            IsActive = active,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        });
        return email;
    }

    private async Task<T> WithContextAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private Task<User> LoadAsync(string email) =>
        WithContextAsync(c => c.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)));

    private Task<List<PasswordResetToken>> ResetLinksAsync(string email) =>
        WithContextAsync(c => c.PasswordResetToken.AsNoTracking().Where(t => t.User.NormalizedEmail == EmailNormalizer.Normalize(email)).ToListAsync());

    private sealed class MutableClock(DateTime start) : IClock
    {
        private long ticks = start.Ticks;

        public DateTime UtcNow => new(Interlocked.Read(ref ticks), DateTimeKind.Utc);

        public void Advance(TimeSpan by) => Interlocked.Add(ref ticks, by.Ticks);
    }
}
