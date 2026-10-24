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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Services;

/// <summary>T12 registration and email verification against SQL Express, with a fake clock, a counting hasher and a captured mailbox.</summary>
public sealed class RegistrationServiceTests : RepositoryTestBase, IAsyncDisposable
{
    private const string Password = "violet-canyon-7319";

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
        Assert.StartsWith("$argon2id$", user.PasswordHash, StringComparison.Ordinal);
        Assert.Equal("Ada Lovelace", user.DisplayName);

        string token = TokenFrom(mailbox.OnlyTo(email));
        EmailVerificationToken row = Assert.Single(await LoadTokensAsync(user.Id));
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
    public async Task Registering_again_before_verifying_sends_a_fresh_link_and_retires_the_old_one()
    {
        string email = UniqueEmail();
        await RegisterAsync(email);
        string oldToken = TokenFrom(mailbox.OnlyTo(email));
        mailbox.Clear();

        await RegisterAsync(email);
        string newToken = TokenFrom(mailbox.OnlyTo(email));

        Assert.NotEqual(oldToken, newToken);
        Assert.Equal(AuthError.InvalidOrExpiredToken, (await VerifyAsync(oldToken)).Error);
        Assert.True((await VerifyAsync(newToken)).IsSuccess);
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

    public async ValueTask DisposeAsync() => await services.DisposeAsync();

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
