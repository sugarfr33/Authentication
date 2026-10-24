using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T14 through the real pipeline: forgot, reset and change password with CSRF, rate limits, cookies and sessions. The
/// limits are raised for this class so the tests do not throttle each other.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class PasswordApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Forgot = "/api/v1/auth/forgot-password";
    private const string Reset = "/api/v1/auth/reset-password";
    private const string Change = "/api/v1/auth/change-password";
    private const string Login = "/api/v1/auth/login";
    private const string Me = "/api/v1/auth/me";
    private const string OldPassword = "violet-canyon-7319";
    private const string NewPassword = "amber-harbor-5826";

    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        Dictionary<string, string?> settings = new();
        foreach (string kind in new[] { "Login", "ForgotPassword", "ResetPassword", "ChangePassword" })
        {
            settings["RateLimiting:Policies:" + kind + ":PerIp:PermitLimit"] = "1000";
        }

        settings["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000";
        settings["RateLimiting:Policies:ForgotPassword:PerAccount:PermitLimit"] = "1000";
        app = api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        });
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task Forgot_password_answers_are_byte_identical_for_every_kind_of_email()
    {
        string verified = await SeedUserAsync();
        string unverified = await SeedUserAsync(verified: false, hash: string.Empty);
        string inactive = await SeedUserAsync(active: false);
        string unknown = "nobody-" + Guid.NewGuid().ToString("N")[..8] + "@example.test";
        using Browser browser = await ReadyBrowserAsync();

        List<(HttpStatusCode, string?, string)> answers = [];
        foreach (string email in new[] { verified, unverified, inactive, unknown, " " + verified.ToUpperInvariant() + " " })
        {
            HttpResponseMessage response = await PostAsync(browser, Forgot, new Dictionary<string, string> { [AuthRequestFields.Email] = email });
            answers.Add((response.StatusCode, response.Content.Headers.ContentType?.ToString(), await response.Content.ReadAsStringAsync()));
        }

        Assert.Equal(HttpStatusCode.Accepted, answers[0].Item1);
        Assert.Single(answers.Distinct());
    }

    [Fact]
    public async Task Reset_signs_out_every_browser_and_only_the_new_password_works()
    {
        string email = await SeedUserAsync();
        using Browser laptop = await ReadyBrowserAsync();
        using Browser phone = await ReadyBrowserAsync();
        await LoginAsync(laptop, email, OldPassword);
        await LoginAsync(phone, email, OldPassword);
        Guid userId = (await LoadUserAsync(email)).Id;

        await PostAsync(laptop, Forgot, new Dictionary<string, string> { [AuthRequestFields.Email] = email });
        HttpResponseMessage reset = await PostAsync(laptop, Reset, new Dictionary<string, string> { ["token"] = LatestToken(email), ["newPassword"] = NewPassword });

        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        List<RefreshToken> families = await RefreshTokensAsync(userId);
        Assert.Equal(2, families.Count);
        Assert.All(families, t => Assert.Equal(RefreshTokenRevokedReason.PasswordChange, t.RevokedReason));
        using Browser fresh = await ReadyBrowserAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(fresh, email, OldPassword)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(fresh, email, NewPassword)).StatusCode);
    }

    [Fact]
    public async Task Bad_reset_links_and_rejected_passwords_get_ProblemDetails()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        await PostAsync(browser, Forgot, new Dictionary<string, string> { [AuthRequestFields.Email] = email });
        string token = LatestToken(email);

        HttpResponseMessage weak = await PostAsync(browser, Reset, new Dictionary<string, string> { ["token"] = token, ["newPassword"] = "short" });
        HttpResponseMessage unknown = await PostAsync(browser, Reset, new Dictionary<string, string> { ["token"] = "not-a-token", ["newPassword"] = NewPassword });

        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.True(JsonNode.Parse(await weak.Content.ReadAsStringAsync())!["errors"]!.AsObject().ContainsKey("newPassword"));
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal("application/problem+json", unknown.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(browser, Reset, new Dictionary<string, string> { ["token"] = token, ["newPassword"] = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task Change_password_needs_the_antiforgery_token_and_the_current_password()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        await LoginAsync(browser, email, OldPassword);
        Dictionary<string, string> wrongCurrent = new() { ["currentPassword"] = "not-the-password-1", ["newPassword"] = NewPassword };

        HttpResponseMessage withoutXsrf = await browser.SendAsync(HttpMethod.Post, Change, sendXsrf: false, configure: r => r.Content = Json(wrongCurrent));
        HttpResponseMessage wrong = await PostAsync(browser, Change, wrongCurrent);
        HttpResponseMessage weak = await PostAsync(browser, Change, new Dictionary<string, string> { ["currentPassword"] = OldPassword, ["newPassword"] = "short" });

        Assert.Equal(HttpStatusCode.BadRequest, withoutXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal("The current password is incorrect.", JsonNode.Parse(await wrong.Content.ReadAsStringAsync())!["title"]!.GetValue<string>());
        Assert.True(JsonNode.Parse(await weak.Content.ReadAsStringAsync())!["errors"]!.AsObject().ContainsKey("newPassword"));
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(Me)).StatusCode);
    }

    [Fact]
    public async Task Change_password_signs_out_every_browser_including_this_one()
    {
        string email = await SeedUserAsync();
        using Browser laptop = await ReadyBrowserAsync();
        using Browser phone = await ReadyBrowserAsync();
        await LoginAsync(laptop, email, OldPassword);
        await LoginAsync(phone, email, OldPassword);
        Guid userId = (await LoadUserAsync(email)).Id;

        HttpResponseMessage change = await PostAsync(laptop, Change, new Dictionary<string, string> { ["currentPassword"] = OldPassword, ["newPassword"] = NewPassword });

        Assert.Equal(HttpStatusCode.NoContent, change.StatusCode);
        Assert.True(Assert.Single(SetCookie.From(change), c => c.Name == AuthCookieNames.Access).IsExpired);
        Assert.False(laptop.HasCookie(AuthCookieNames.Refresh));
        Assert.All(await RefreshTokensAsync(userId), t => Assert.Equal(RefreshTokenRevokedReason.PasswordChange, t.RevokedReason));
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(laptop, email, OldPassword)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(laptop, email, NewPassword)).StatusCode);
    }

    [Fact]
    public async Task Change_password_needs_a_signed_in_user()
    {
        using Browser browser = await ReadyBrowserAsync();

        HttpResponseMessage response = await PostAsync(browser, Change, new Dictionary<string, string> { ["currentPassword"] = OldPassword, ["newPassword"] = NewPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Reset_tokens_and_passwords_never_reach_the_logs()
    {
        string email = await SeedUserAsync();
        using Browser browser = await ReadyBrowserAsync();
        await PostAsync(browser, Forgot, new Dictionary<string, string> { [AuthRequestFields.Email] = email });
        string token = LatestToken(email);
        await PostAsync(browser, Reset, new Dictionary<string, string> { ["token"] = token, ["newPassword"] = NewPassword });
        await LoginAsync(browser, email, NewPassword);
        await PostAsync(browser, Change, new Dictionary<string, string> { ["currentPassword"] = NewPassword, ["newPassword"] = "third-password-4417" });

        Assert.DoesNotContain(api.Logs.Texts, t => t.Contains(token, StringComparison.Ordinal)
            || t.Contains(NewPassword, StringComparison.Ordinal)
            || t.Contains("third-password-4417", StringComparison.Ordinal));
    }

    private static StringContent Json(Dictionary<string, string> body) => new(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    private static Task<HttpResponseMessage> PostAsync(Browser browser, string path, Dictionary<string, string> body) =>
        browser.SendAsync(HttpMethod.Post, path, configure: r => r.Content = Json(body));

    private static Task<HttpResponseMessage> LoginAsync(Browser browser, string email, string password) =>
        PostAsync(browser, Login, new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = password });

    private string LatestToken(string email)
    {
        EmailMessage message = api.Emails.Messages.Last(m => string.Equals(m.To, email, StringComparison.OrdinalIgnoreCase) && m.Body.Contains("#token=", StringComparison.Ordinal));
        int start = message.Body.IndexOf("#token=", StringComparison.Ordinal) + "#token=".Length;
        return new string(message.Body[start..].TakeWhile(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray());
    }

    private async Task<Browser> ReadyBrowserAsync()
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return browser;
    }

    private async Task<string> SeedUserAsync(bool verified = true, bool active = true, string? hash = null)
    {
        string email = "pwdapi-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string passwordHash = hash ?? await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(OldPassword, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        context.User.Add(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = verified,
            PasswordHash = passwordHash,
            DisplayName = "Password Api Tester",
            IsActive = active,
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

    private Task<User> LoadUserAsync(string email) =>
        QueryAsync(context => context.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)));

    private Task<List<RefreshToken>> RefreshTokensAsync(Guid userId) =>
        QueryAsync(context => context.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync());
}
