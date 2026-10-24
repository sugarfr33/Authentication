using System.Net;
using System.Text;
using System.Text.Json;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Passwords;
using Auth.Services.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T16 prerequisite 2: an old access cookie stops working once its session ends, without waiting 15 minutes. The
/// fixture sets the cache duration to 0, so each case shows the effect immediately.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class LiveSessionApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Login = "/api/v1/auth/login";
    private const string Sessions = "/api/v1/auth/sessions";
    private const string Password = "violet-canyon-7319";

    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        app = WithSettings(api.Factory);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task Logout_all_elsewhere_ends_this_access_cookie_at_once()
    {
        string email = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(email);
        using Browser phone = await SignedInAsync(email);
        Assert.Equal(HttpStatusCode.OK, (await laptop.GetAsync(Sessions)).StatusCode);

        await phone.SendAsync(HttpMethod.Post, "/api/v1/auth/logout-all");

        Assert.Equal(HttpStatusCode.Unauthorized, (await laptop.GetAsync(Sessions)).StatusCode);
    }

    [Fact]
    public async Task A_password_change_elsewhere_ends_this_access_cookie_at_once()
    {
        string email = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(email);
        using Browser phone = await SignedInAsync(email);

        HttpResponseMessage change = await phone.SendAsync(HttpMethod.Post, "/api/v1/auth/change-password", configure: r =>
            r.Content = Json(new Dictionary<string, string> { ["currentPassword"] = Password, ["newPassword"] = "amber-harbor-5826" }));

        Assert.Equal(HttpStatusCode.NoContent, change.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await laptop.GetAsync(Sessions)).StatusCode);
    }

    [Fact]
    public async Task Deactivating_the_account_ends_its_access_cookies_at_once()
    {
        string email = await SeedUserAsync();
        using Browser laptop = await SignedInAsync(email);

        await QueryAsync(c => c.User.Where(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)).ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false)));

        Assert.Equal(HttpStatusCode.Unauthorized, (await laptop.GetAsync(Sessions)).StatusCode);
    }

    [Fact]
    public async Task A_failing_session_check_fails_closed_with_a_bare_401()
    {
        string email = await SeedUserAsync();
        await using WebApplicationFactory<Program> broken = app.WithWebHostBuilder(b => b.ConfigureServices(s => s.AddSingleton<ISessionLiveness, BrokenLiveness>()));
        using Browser browser = new(broken);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        await browser.SendAsync(HttpMethod.Post, Login, configure: r => r.Content = Json(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }));

        HttpResponseMessage response = await browser.GetAsync(Sessions);
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("database down", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Exception", body, StringComparison.Ordinal);
        Assert.Contains(api.Logs.Texts, t => t.Contains("Live-session check failed", StringComparison.Ordinal) && t.Contains("InvalidOperationException", StringComparison.Ordinal));
    }

    private static WebApplicationFactory<Program> WithSettings(WebApplicationFactory<Program> factory)
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Sessions:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:ChangePassword:PerIp:PermitLimit"] = "1000",
        };
        return factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        });
    }

    private static StringContent Json(Dictionary<string, string> body) => new(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    private async Task<Browser> SignedInAsync(string email)
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage login = await browser.SendAsync(HttpMethod.Post, Login, configure: r =>
            r.Content = Json(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = Password }));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return browser;
    }

    private async Task<string> SeedUserAsync()
    {
        string email = "live-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        context.User.Add(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = true,
            PasswordHash = hash,
            DisplayName = "Live Tester",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        });
        await context.SaveChangesAsync();
        return email;
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    private sealed class BrokenLiveness : ISessionLiveness
    {
        public Task<bool> IsLiveAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("database down");
    }
}
