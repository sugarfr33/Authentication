using System.Data.SqlTypes;
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

/// <summary>T12 registration and email verification against SQL Express, with a fake clock, a counting hasher and a captured mailbox.</summary>
public sealed class RegistrationServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private const string Password = "violet-canyon-7319";
    private const string AttackerPassword = "attacker-chosen-8812";
    private const string VictimPassword = "victim-chosen-2297";

    private readonly MutableClock clock = new(TestData.Now);
    private readonly CapturingEmailSender mailbox = new();
    private readonly ServiceProvider services;
    private CountingHasher? hasher;

    public RegistrationServiceTests(SqlServerDatabaseFixture database)
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
        collection.AddSingleton(new AccountEmailOptions { VerifyEmailUrl = new Uri("https://app.example.test/verify-email") });
        collection.AddSingleton<IEmailSender>(mailbox);
        collection.AddAuthServices(configuration);
        ServiceDescriptor real = collection.Last(d => d.ServiceType == typeof(IPasswordHasher));
        collection.AddSingleton<IPasswordHasher>(sp => hasher = new CountingHasher((IPasswordHasher)real.ImplementationFactory!(sp)));
        services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private CountingHasher Hasher => hasher ?? services.GetRequiredService<IPasswordHasher>() as CountingHasher ?? throw new InvalidOperationException();

    [Fact]
    public async Task New_account_is_unverified_with_an_argon2_hash_and_a_hashed_expiring_token()
    {
        string email = UniqueEmail();

        RegistrationResult result = await RegisterAsync("  " + email.ToUpperInvariant() + " ", "Ada Lovelace");

        Assert.True(result.IsAccepted);
        User user = await LoadUserAsync(email);
        Assert.Equal(email.ToUpperInvariant(), user.Email);
        Assert.Equal(EmailNormalizer.Normalize(email), user.NormalizedEmail);
        Assert.False(user.EmailVerified);
        Assert.True(user.IsActive);
        Assert.Equal(string.Empty, user.PasswordHash);
        Assert.Equal("Ada Lovelace", user.DisplayName);
        Assert.False(await SignsInAsync(email, Password));

        string token = TokenFrom(mailbox.OnlyTo(email));
        EmailVerificationToken row = Assert.Single(await LoadTokensAsync(user.Id));
        Assert.StartsWith("$argon2id$", row.PendingPasswordHash, StringComparison.Ordinal);
        Assert.Equal("Ada Lovelace", row.PendingDisplayName);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(token)), row.TokenHash);
        Assert.Equal(43, token.Length);
        Assert.Null(row.UsedUtc);
        Assert.Equal(clock.UtcNow.AddHours(24), row.ExpiresUtc);
        Assert.Contains(await LoadAuditAsync(user.Id), a => a.EventType == nameof(AuditEventType.Registered));
    }

    [Fact]
    public async Task Duplicate_email_gets_the_same_answer_and_the_same_work_as_a_new_one()
    {
        string email = UniqueEmail();

        (RegistrationResult first, int firstHashes, int firstVerifies, int firstMails) = await MeasureAsync(() => RegisterAsync(email));
        await VerifyAsync(TokenFrom(mailbox.OnlyTo(email)));
        mailbox.Clear();
        (RegistrationResult duplicate, int dupHashes, int dupVerifies, int dupMails) = await MeasureAsync(() => RegisterAsync(" " + email.ToUpperInvariant(), "Someone Else", "another-password-4821"));

        Assert.Same(RegistrationResult.Accepted, first);
        Assert.Same(RegistrationResult.Accepted, duplicate);
        Assert.Equal((1, 0, 1), (firstHashes, firstVerifies, firstMails));
        Assert.Equal((1, 0, 1), (dupHashes, dupVerifies, dupMails));

        EmailMessage notice = mailbox.OnlyTo(email);
        Assert.DoesNotContain("#token=", notice.Body, StringComparison.Ordinal);
        User user = await LoadUserAsync(email);
        Assert.Equal("Test User", user.DisplayName);
        Assert.Equal(PasswordVerifyResult.Success, services.GetRequiredService<IPasswordHasher>().Verify(Password, user.PasswordHash));
    }

    [Fact]
    public async Task Registering_again_before_verifying_adds_a_link_and_never_changes_an_earlier_links_password()
    {
        string email = UniqueEmail();
        await RegisterAsync(email, "First Name", Password);
        await RegisterAsync(email, "Second Name", "second-password-5530");
        (string firstToken, string secondToken) = (TokenFrom(mailbox.To(email)[0]), TokenFrom(mailbox.To(email)[1]));

        Assert.NotEqual(firstToken, secondToken);
        Assert.True((await VerifyAsync(firstToken)).IsSuccess);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(secondToken)).Error);
        Assert.True(await SignsInAsync(email, Password));
        Assert.False(await SignsInAsync(email, "second-password-5530"));
        Assert.Equal("First Name", (await LoadUserAsync(email)).DisplayName);
    }

    /// <summary>Review HIGH-1: the attacker registers the victim's email first; the victim's own link must activate only the victim's password.</summary>
    [Fact]
    public async Task Pre_hijacking_attacker_first_victim_link_activates_only_the_victim_password()
    {
        string email = UniqueEmail();
        await RegisterAsync(email, "Attacker", AttackerPassword);
        await RegisterAsync(email, "Victim", VictimPassword);
        string victimLink = TokenFrom(mailbox.To(email)[1]);

        Assert.False(await SignsInAsync(email, AttackerPassword));
        Assert.False(await SignsInAsync(email, VictimPassword));
        Assert.True((await VerifyAsync(victimLink)).IsSuccess);

        Assert.True(await SignsInAsync(email, VictimPassword));
        Assert.False(await SignsInAsync(email, AttackerPassword));
        Assert.Equal("Victim", (await LoadUserAsync(email)).DisplayName);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(TokenFrom(mailbox.To(email)[0]))).Error);
    }

    [Fact]
    public async Task Pre_hijacking_victim_first_attacker_registering_later_cannot_take_over()
    {
        string email = UniqueEmail();
        await RegisterAsync(email, "Victim", VictimPassword);
        await RegisterAsync(email, "Attacker", AttackerPassword);
        string victimLink = TokenFrom(mailbox.To(email)[0]);
        string attackerLink = TokenFrom(mailbox.To(email)[1]);

        Assert.True((await VerifyAsync(victimLink)).IsSuccess);
        await RegisterAsync(email, "Attacker", AttackerPassword);

        Assert.True(await SignsInAsync(email, VictimPassword));
        Assert.False(await SignsInAsync(email, AttackerPassword));
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(attackerLink)).Error);
        Assert.True(await SignsInAsync(email, VictimPassword));
        Assert.DoesNotContain("#token=", mailbox.To(email)[2].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verification_rotates_the_security_stamp_and_revokes_every_refresh_token()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        User before = await LoadUserAsync(email);
        await using (AsyncServiceScope scope = services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IRefreshTokenService>()
                .IssueAsync(before.Id, null, new RefreshContext("203.0.113.9", "tests"), Ct);
        }

        Assert.True((await VerifyAsync(TokenFrom(mailbox.OnlyTo(email)))).IsSuccess);

        User after = await LoadUserAsync(email);
        Assert.NotEqual(before.SecurityStamp, after.SecurityStamp);
        List<RefreshToken> sessions = await WithContextAsync(context => context.RefreshToken.AsNoTracking().Where(t => t.UserId == before.Id).ToListAsync());
        RefreshToken session = Assert.Single(sessions);
        Assert.NotNull(session.RevokedUtc);
        Assert.Equal(RefreshTokenRevokedReason.PasswordChange, session.RevokedReason);
    }

    /// <summary>Review LOW-1: keys come from EF's client-side sequential generator, so they ascend in SQL Server order.</summary>
    [Fact]
    public async Task New_user_and_link_ids_ascend_in_SQL_Server_order()
    {
        List<Guid> userIds = [];
        List<Guid> tokenIds = [];
        for (int i = 0; i < 5; i++)
        {
            string email = UniqueEmail();
            await RegisterAsync(email);
            User user = await LoadUserAsync(email);
            userIds.Add(user.Id);
            tokenIds.Add(Assert.Single(await LoadTokensAsync(user.Id)).Id);
        }

        Assert.True(IsAscending(userIds), "User ids are not sequential.");
        Assert.True(IsAscending(tokenIds), "Link ids are not sequential.");
    }

    [Fact]
    public async Task Verification_token_is_single_use_and_marks_the_email_verified()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));

        Result first = await VerifyAsync(token);
        Result reused = await VerifyAsync(token);

        Assert.True(first.IsSuccess);
        Assert.Equal(AuthError.InvalidOrExpiredToken, reused.Error);
        User user = await LoadUserAsync(email);
        Assert.True(user.EmailVerified);
        Assert.NotNull(Assert.Single(await LoadTokensAsync(user.Id)).UsedUtc);
        Assert.Contains(await LoadAuditAsync(user.Id), a => a.EventType == nameof(AuditEventType.EmailVerified));
    }

    [Fact]
    public async Task Concurrent_redemptions_of_one_token_succeed_exactly_once()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));

        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<Result>[] racers = [.. Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            await start.Task;
            return await VerifyAsync(token);
        }))];
        start.SetResult();
        Result[] results = await Task.WhenAll(racers);

        Assert.Equal(1, results.Count(r => r.IsSuccess));
        Assert.All(results.Where(r => !r.IsSuccess), r => Assert.Equal(AuthError.InvalidOrExpiredToken, r.Error));
    }

    [Fact]
    public async Task Expired_token_is_rejected_and_leaves_the_email_unverified()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));

        clock.Advance(TimeSpan.FromHours(24));
        Result result = await VerifyAsync(token);

        Assert.Equal(AuthError.InvalidOrExpiredToken, result.Error);
        Assert.False((await LoadUserAsync(email)).EmailVerified);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-real-token")]
    public async Task Unknown_or_empty_tokens_are_rejected(string? token)
    {
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(token)).Error);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(new string('a', 300))).Error);
    }

    [Fact]
    public async Task Inactive_account_cannot_be_verified()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));
        await WithContextAsync(context => context.User.Where(u => u.NormalizedEmail == EmailNormalizer.Normalize(email))
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false)));

        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(token)).Error);
        Assert.False((await LoadUserAsync(email)).EmailVerified);
    }

    [Fact]
    public async Task Invalid_input_is_rejected_before_any_hashing_lookup_or_email()
    {
        Hasher.Reset();

        RegistrationResult result = await InScopeAsync(s => s.RegisterAsync(new RegisterRequest("not-an-email", "short", "  "), AuditContext.None, Ct));

        Assert.False(result.IsAccepted);
        Assert.Equal(["displayName", "email", "password"], result.ValidationErrors.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(0, Hasher.HashCalls);
        Assert.Empty(mailbox.Messages);
    }

    /// <summary>Audit LOW-1: a spent or retired link keeps no password hash or display name.</summary>
    [Fact]
    public async Task Redeemed_and_retired_links_keep_no_pending_password_or_name()
    {
        string email = UniqueEmail();
        await RegisterAsync(email, "First", Password);
        await RegisterAsync(email, "Second", "second-password-5530");
        Assert.All(await LoadTokensAsync((await LoadUserAsync(email)).Id), t => Assert.NotNull(t.PendingPasswordHash));

        Assert.True((await VerifyAsync(TokenFrom(mailbox.To(email)[0]))).IsSuccess);

        List<EmailVerificationToken> links = await LoadTokensAsync((await LoadUserAsync(email)).Id);
        Assert.Equal(2, links.Count);
        Assert.All(links, t =>
        {
            Assert.NotNull(t.UsedUtc);
            Assert.Null(t.PendingPasswordHash);
            Assert.Null(t.PendingDisplayName);
        });
        Assert.True(await SignsInAsync(email, Password));
        Assert.Equal("First", (await LoadUserAsync(email)).DisplayName);
    }

    /// <summary>Audit LOW-4: failed redemptions are audited with a reason, never the token.</summary>
    [Fact]
    public async Task Failed_verifications_are_audited_with_a_reason_and_without_the_token()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        string token = TokenFrom(mailbox.OnlyTo(email));
        Guid userId = (await LoadUserAsync(email)).Id;
        string correlation = "verify-" + Guid.NewGuid().ToString("N")[..8];
        AuditContext audit = new("203.0.113.77", "probe-agent", correlation);

        await InScopeAsync(s => s.VerifyEmailAsync("no-such-token-value", audit, Ct));
        await InScopeAsync(s => s.VerifyEmailAsync(token, audit, Ct));
        await InScopeAsync(s => s.VerifyEmailAsync(token, audit, Ct));
        await InScopeAsync(s => s.VerifyEmailAsync(string.Empty, audit, Ct));

        List<AuditLog> rows = await WithContextAsync(context => context.AuditLog.AsNoTracking()
            .Where(a => a.CorrelationId == correlation).OrderBy(a => a.Id).ToListAsync());
        Assert.Equal(
            [nameof(AuditEventType.EmailVerificationFailed), nameof(AuditEventType.EmailVerified), nameof(AuditEventType.EmailVerificationFailed), nameof(AuditEventType.EmailVerificationFailed)],
            rows.Select(r => r.EventType));
        Assert.Equal(["""{"reason":"unknown"}""", null, """{"reason":"used"}""", """{"reason":"malformed"}"""], rows.Select(r => r.Detail));
        Assert.Equal([null, userId, userId, null], rows.Select(r => r.UserId));
        Assert.All(rows, r => Assert.Equal(("203.0.113.77", "probe-agent"), (r.IpAddress, r.UserAgent)));
        Assert.DoesNotContain(rows, r => (r.Detail ?? string.Empty).Contains(token, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Rejected_registrations_are_audited_with_field_names_only()
    {
        string correlation = "reject-" + Guid.NewGuid().ToString("N")[..8];

        await InScopeAsync(s => s.RegisterAsync(new RegisterRequest("bad@@example", "short", "Ok Name"), new AuditContext("203.0.113.78", "probe", correlation), Ct));

        AuditLog row = Assert.Single(await WithContextAsync(context => context.AuditLog.AsNoTracking().Where(a => a.CorrelationId == correlation).ToListAsync()));
        Assert.Equal(nameof(AuditEventType.RegistrationRejected), row.EventType);
        Assert.Equal("""{"fields":["email","password"]}""", row.Detail);
        Assert.Null(row.UserId);
    }

    /// <summary>Audit MEDIUM-1 mitigation: every link email names the sign-up it confirms and says not to open it otherwise.</summary>
    [Fact]
    public async Task Link_emails_name_the_sign_up_time_and_warn_not_to_open_someone_elses()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        clock.Advance(TimeSpan.FromMinutes(7));
        await RegisterAsync(email);

        IReadOnlyList<EmailMessage> messages = mailbox.To(email);
        Assert.Contains(TestData.Now.ToString("yyyy-MM-dd 'at' HH:mm 'UTC'", System.Globalization.CultureInfo.InvariantCulture), messages[0].Body, StringComparison.Ordinal);
        Assert.Contains(TestData.Now.AddMinutes(7).ToString("yyyy-MM-dd 'at' HH:mm 'UTC'", System.Globalization.CultureInfo.InvariantCulture), messages[1].Body, StringComparison.Ordinal);
        Assert.All(messages, m => Assert.Contains("do NOT open the link", m.Body, StringComparison.Ordinal));
    }

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

    private static bool IsAscending(List<Guid> ids) =>
        ids.Zip(ids.Skip(1)).All(pair => new SqlGuid(pair.First).CompareTo(new SqlGuid(pair.Second)) < 0);

    /// <summary>Stand-in for the T13 sign-in check: the timing guard over the stored hash, usable only once verified and active.</summary>
    private async Task<bool> SignsInAsync(string email, string password)
    {
        User user = await LoadUserAsync(email);
        CredentialCheck check = await services.GetRequiredService<IAuthTimingGuard>()
            .CheckPasswordAsync(password, user.PasswordHash, accountUsable: user.IsActive && user.EmailVerified, Ct);
        return check is CredentialCheck.Valid or CredentialCheck.ValidNeedsRehash;
    }

    private static string UniqueEmail() => "reg-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";

    private static string TokenFrom(EmailMessage message)
    {
        const string marker = "#token=";
        int start = message.Body.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The email holds no verification link.");
        return new string(message.Body[(start + marker.Length)..].TakeWhile(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray());
    }

    private async Task<(RegistrationResult Result, int Hashes, int Verifies, int Mails)> MeasureAsync(Func<Task<RegistrationResult>> action)
    {
        Hasher.Reset();
        int mailsBefore = mailbox.Messages.Count;
        RegistrationResult result = await action();
        return (result, Hasher.HashCalls, Hasher.VerifyCalls, mailbox.Messages.Count - mailsBefore);
    }

    private Task<RegistrationResult> RegisterAsync(string email, string displayName = "Test User", string password = Password) =>
        InScopeAsync(s => s.RegisterAsync(new RegisterRequest(email, password, displayName), new AuditContext("203.0.113.9", "tests", "corr-1"), Ct));

    private Task<Result> VerifyAsync(string? token) => InScopeAsync(s => s.VerifyEmailAsync(token, AuditContext.None, Ct));

    private async Task<T> InScopeAsync<T>(Func<IRegistrationService, Task<T>> action)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<IRegistrationService>());
    }

    private async Task<T> WithContextAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private Task<User> LoadUserAsync(string email) =>
        WithContextAsync(context => context.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)));

    private Task<List<EmailVerificationToken>> LoadTokensAsync(Guid userId) =>
        WithContextAsync(context => context.EmailVerificationToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync());

    private Task<List<AuditLog>> LoadAuditAsync(Guid userId) =>
        WithContextAsync(context => context.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());

    private sealed class MutableClock(DateTime start) : IClock
    {
        private long ticks = start.Ticks;

        public DateTime UtcNow => new(Interlocked.Read(ref ticks), DateTimeKind.Utc);

        public void Advance(TimeSpan by) => Interlocked.Add(ref ticks, by.Ticks);
    }

    private sealed class CountingHasher(IPasswordHasher inner) : IPasswordHasher
    {
        private int hashCalls;
        private int verifyCalls;

        public int HashCalls => Volatile.Read(ref hashCalls);

        public int VerifyCalls => Volatile.Read(ref verifyCalls);

        public void Reset() => (hashCalls, verifyCalls) = (0, 0);

        public string Hash(string password) => throw new InvalidOperationException("Request paths must use HashAsync.");

        public PasswordVerifyResult Verify(string password, string storedHash) => inner.Verify(password, storedHash);

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

/// <summary>Collects sent emails instead of delivering them.</summary>
public sealed class CapturingEmailSender : IEmailSender
{
    private readonly List<EmailMessage> messages = [];

    public IReadOnlyList<EmailMessage> Messages
    {
        get
        {
            lock (messages)
            {
                return [.. messages];
            }
        }
    }

    /// <summary>Messages to one address, in the order they were sent.</summary>
    public IReadOnlyList<EmailMessage> To(string to) => [.. Messages.Where(m => string.Equals(m.To.Trim(), to.Trim(), StringComparison.OrdinalIgnoreCase))];

    public EmailMessage OnlyTo(string to) => Assert.Single(Messages, m => string.Equals(m.To.Trim(), to.Trim(), StringComparison.OrdinalIgnoreCase));

    public void Clear()
    {
        lock (messages)
        {
            messages.Clear();
        }
    }

    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        lock (messages)
        {
            messages.Add(message);
        }

        return Task.CompletedTask;
    }
}
