using System.Net;
using System.Text;
using System.Text.Json;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T25: end-to-end security scenarios through the real pipeline that the service-level suites cover but no HTTP test
/// did (docs/test-matrix.md): browser refresh rotation and reuse detection, and the lockout with its two decays. The
/// host gets a clock that tests can move forward, so grace windows and lock durations are crossed without waiting.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class SecurityScenarioApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Login = "/api/v1/auth/login";
    private const string Refresh = "/api/v1/auth/refresh";
    private const string Me = "/api/v1/auth/me";
    private const string Password = "copper-meadow-6142";
    private const string WrongPassword = "copper-meadow-0000";

    private readonly ShiftableClock clock = new();
    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "100000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "100000",
            ["RateLimiting:Policies:Refresh:PerIp:PermitLimit"] = "100000",
        };
        app = api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
            builder.ConfigureTestServices(services => services.AddSingleton<IClock>(clock));
        });
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task Refresh_rotates_the_cookie_and_a_replayed_old_token_revokes_the_whole_family_and_is_audited()
    {
        (Guid userId, string email) = await SeedUserAsync();
        using Browser victim = await SignedInAsync(email);
        string first = victim.CookieValue(AuthCookieNames.Refresh);

        Assert.Equal(HttpStatusCode.NoContent, (await victim.SendAsync(HttpMethod.Post, Refresh)).StatusCode);
        string second = victim.CookieValue(AuthCookieNames.Refresh);
        Assert.NotEqual(first, second);
        Assert.Equal(HttpStatusCode.OK, (await victim.GetAsync(Me)).StatusCode);

        List<RefreshToken> rotated = await TokensAsync(userId);
        Assert.Equal(2, rotated.Count);
        Assert.Single(rotated.Select(t => t.FamilyId).Distinct());
        Assert.Equal(RefreshTokenRevokedReason.Rotated, Assert.Single(rotated, t => t.RevokedUtc is not null).RevokedReason);

        // A thief replays the first token after the 10 s grace window.
        clock.Shift(TimeSpan.FromSeconds(11));
        using Browser thief = new(app);
        await thief.GetAsync(TestEndpoints.Prefix + "/ping");
        thief.Plant(AuthCookieNames.Refresh, first, "/api/v1/auth");
        Assert.Equal(HttpStatusCode.Unauthorized, (await thief.SendAsync(HttpMethod.Post, Refresh)).StatusCode);

        // The whole family is gone: the victim's access cookie and current refresh token stop working too. The GET
        // comes first, as in the SPA: it re-issues the antiforgery token for the now anonymous browser.
        Assert.Equal(HttpStatusCode.Unauthorized, (await victim.GetAsync(Me)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await victim.SendAsync(HttpMethod.Post, Refresh)).StatusCode);
        Assert.All(await TokensAsync(userId), t => Assert.NotNull(t.RevokedUtc));
        Assert.Contains(await TokensAsync(userId), t => t.RevokedReason == RefreshTokenRevokedReason.Reuse);
        Assert.Single(await AuditAsync(userId, AuditEventType.TokenReuse));
    }

    [Fact]
    public async Task Within_the_grace_window_a_double_submitted_refresh_from_the_same_browser_is_not_reuse()
    {
        (Guid userId, string email) = await SeedUserAsync();
        using Browser browser = await SignedInAsync(email);
        string first = browser.CookieValue(AuthCookieNames.Refresh);
        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(HttpMethod.Post, Refresh)).StatusCode);

        // A second tab sends the old cookie a moment later (same user agent, inside the grace window).
        using Browser tab = new(app);
        await tab.GetAsync(TestEndpoints.Prefix + "/ping");
        tab.Plant(AuthCookieNames.Refresh, first, "/api/v1/auth");
        await tab.SendAsync(HttpMethod.Post, Refresh);

        Assert.Equal(HttpStatusCode.NoContent, (await browser.SendAsync(HttpMethod.Post, Refresh)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(Me)).StatusCode);
        Assert.Empty(await AuditAsync(userId, AuditEventType.TokenReuse));
    }

    [Fact]
    public async Task Old_failures_decay_one_per_quiet_hour_so_paced_guessing_never_reaches_the_lock()
    {
        (_, string paced) = await SeedUserAsync();
        (_, string burst) = await SeedUserAsync();

        // Without a pause, five wrong passwords lock the account; the right one then fails the same way.
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(burst, WrongPassword)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(burst, Password)).StatusCode);

        // Four failures, then a quiet hour decays one: the fifth failure leaves the count at four, not locked.
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(paced, WrongPassword)).StatusCode);
        }

        clock.Shift(TimeSpan.FromMinutes(61));
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(paced, WrongPassword)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(paced, Password)).StatusCode);
    }

    [Fact]
    public async Task Each_lock_doubles_until_a_quiet_day_forgets_the_backoff()
    {
        (Guid userId, string email) = await SeedUserAsync();

        // First lock: one minute.
        await FailAsync(email, 5);
        clock.Shift(TimeSpan.FromSeconds(61));

        // Second lock right after: two minutes, so one minute later the right password still fails.
        await FailAsync(email, 5);
        clock.Shift(TimeSpan.FromSeconds(61));
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(email, Password)).StatusCode);
        Assert.Equal(2, (await LoadUserAsync(userId)).LockoutLevel);

        // A quiet day resets the level: the third lock is one minute again.
        clock.Shift(TimeSpan.FromHours(25));
        await FailAsync(email, 5);
        Assert.Equal(1, (await LoadUserAsync(userId)).LockoutLevel);
        clock.Shift(TimeSpan.FromSeconds(61));
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(email, Password)).StatusCode);
        Assert.Equal(3, (await AuditAsync(userId, AuditEventType.Lockout)).Count);
    }

    private async Task FailAsync(string email, int times)
    {
        for (int i = 0; i < times; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(email, WrongPassword)).StatusCode);
        }
    }

    private async Task<HttpResponseMessage> LoginAsync(string email, string password)
    {
        using Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return await PostLoginAsync(browser, email, password);
    }

    private static Task<HttpResponseMessage> PostLoginAsync(Browser browser, string email, string password) =>
        browser.SendAsync(HttpMethod.Post, Login, configure: r =>
            r.Content = new StringContent(
                JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = password }),
                Encoding.UTF8,
                "application/json"));

    private async Task<Browser> SignedInAsync(string email)
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(browser, email, Password)).StatusCode);
        await browser.GetAsync(Me);
        return browser;
    }

    private async Task<(Guid Id, string Email)> SeedUserAsync()
    {
        string email = "scenario-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = clock.UtcNow;
        User user = new()
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = true,
            PasswordHash = hash,
            DisplayName = "Scenario Tester",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        };
        context.User.Add(user);
        await context.SaveChangesAsync();
        return (user.Id, email);
    }

    private Task<List<RefreshToken>> TokensAsync(Guid userId) =>
        QueryAsync(context => context.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).OrderBy(t => t.CreatedUtc).ToListAsync());

    private Task<User> LoadUserAsync(Guid userId) => QueryAsync(context => context.User.AsNoTracking().SingleAsync(u => u.Id == userId));

    private Task<List<AuditLog>> AuditAsync(Guid userId, AuditEventType type)
    {
        string name = type.ToString();
        return QueryAsync(context => context.AuditLog.AsNoTracking().Where(a => a.UserId == userId && a.EventType == name).ToListAsync());
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private sealed class ShiftableClock : IClock
    {
        private long offsetTicks;

        public DateTime UtcNow => DateTime.UtcNow.AddTicks(Interlocked.Read(ref offsetTicks));

        public void Shift(TimeSpan by) => Interlocked.Add(ref offsetTicks, by.Ticks);
    }
}
