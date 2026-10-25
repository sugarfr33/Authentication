using System.Net;
using System.Text;
using System.Text.Json;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Accounts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T17 acceptance: one account's whole life through the real pipeline, with planted secrets (passwords, link tokens,
/// cookies). Every listed event is persisted, and no audit column and no log line ever holds a secret.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed partial class AuditTrailApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string FirstPassword = "Plant-Secret-Alpha-4471";
    private const string WrongPassword = "Plant-Secret-Wrong-9182";
    private const string WrongCurrent = "Plant-Secret-Current-3355";
    private const string SecondPassword = "Plant-Secret-Bravo-2208";
    private const string ThirdPassword = "Plant-Secret-Charlie-6630";
    private const string RejectedPassword = "Plant7";
    private const string ForgedToken = "PlantSecretForgedTokenValue0123456789abcdefg";

    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        Dictionary<string, string?> settings = new();
        foreach (string kind in new[] { "Login", "Refresh", "Register", "ForgotPassword", "ResetPassword", "VerifyEmail", "ChangePassword" })
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
    public async Task Every_account_event_is_persisted_and_no_row_or_log_line_holds_a_secret()
    {
        DateTime started = DateTime.UtcNow.AddSeconds(-1);
        string email = "trail-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        List<string> secrets = [FirstPassword, WrongPassword, WrongCurrent, SecondPassword, ThirdPassword, ForgedToken];
        using Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        // Sign-up: one rejected (weak password), one accepted, the link used once and then a forged one.
        Expect(HttpStatusCode.BadRequest, await PostAsync(browser, "register", new() { [AuthRequestFields.Email] = email, ["password"] = RejectedPassword, ["displayName"] = "Trail" }));
        Expect(HttpStatusCode.Accepted, await PostAsync(browser, "register", new() { [AuthRequestFields.Email] = email, ["password"] = FirstPassword, ["displayName"] = "Trail" }));
        string verifyToken = LatestToken(email);
        secrets.Add(verifyToken);
        Expect(HttpStatusCode.NoContent, await PostAsync(browser, "verify-email", new() { ["token"] = verifyToken }));
        Expect(HttpStatusCode.BadRequest, await PostAsync(browser, "verify-email", new() { ["token"] = ForgedToken }));
        Expect(HttpStatusCode.Accepted, await PostAsync(browser, "register", new() { [AuthRequestFields.Email] = email, ["password"] = WrongPassword, ["displayName"] = "Trail again" }));

        // Sign-in, refresh, change password (wrong current, weak new, then real).
        Expect(HttpStatusCode.Unauthorized, await PostAsync(browser, "login", new() { [AuthRequestFields.Email] = email, ["password"] = WrongPassword }));
        Expect(HttpStatusCode.OK, await PostAsync(browser, "login", new() { [AuthRequestFields.Email] = email, ["password"] = FirstPassword }));
        secrets.Add(browser.CookieValue(AuthCookieNames.Refresh));
        secrets.Add(browser.CookieValue(AuthCookieNames.Access));
        Expect(HttpStatusCode.NoContent, await PostAsync(browser, "refresh", []));
        secrets.Add(browser.CookieValue(AuthCookieNames.Refresh));
        Expect(HttpStatusCode.BadRequest, await PostAsync(browser, "change-password", new() { ["currentPassword"] = WrongCurrent, ["newPassword"] = SecondPassword }));
        Expect(HttpStatusCode.BadRequest, await PostAsync(browser, "change-password", new() { ["currentPassword"] = FirstPassword, ["newPassword"] = RejectedPassword }));
        Expect(HttpStatusCode.NoContent, await PostAsync(browser, "change-password", new() { ["currentPassword"] = FirstPassword, ["newPassword"] = SecondPassword }));

        // Forgot and reset: a forged link, then the real one.
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        Expect(HttpStatusCode.Accepted, await PostAsync(browser, "forgot-password", new() { [AuthRequestFields.Email] = email }));
        string resetToken = LatestToken(email);
        secrets.Add(resetToken);
        Expect(HttpStatusCode.BadRequest, await PostAsync(browser, "reset-password", new() { ["token"] = ForgedToken, ["newPassword"] = ThirdPassword }));
        Expect(HttpStatusCode.NoContent, await PostAsync(browser, "reset-password", new() { ["token"] = resetToken, ["newPassword"] = ThirdPassword }));

        User user = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.NormalizedEmail == EmailNormalizer.Normalize(email)));
        secrets.Add(user.PasswordHash);
        List<AuditLog> rows = await QueryAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == user.Id || (a.UserId == null && a.OccurredUtc >= started)).ToListAsync());
        List<string> mine = [.. rows.Where(r => r.UserId == user.Id).Select(r => r.EventType)];

        foreach (AuditEventType expected in new[]
        {
            AuditEventType.Registered, AuditEventType.RegistrationDuplicate, AuditEventType.EmailVerified, AuditEventType.LoginFailed, AuditEventType.LoginSucceeded,
            AuditEventType.TokenRefreshed, AuditEventType.PasswordChangeFailed, AuditEventType.PasswordChanged,
            AuditEventType.PasswordResetRequested, AuditEventType.PasswordReset,
        })
        {
            Assert.True(mine.Contains(expected.ToString()), expected + " was not persisted");
        }

        Assert.Equal(2, mine.Count(e => e == nameof(AuditEventType.PasswordChangeFailed)));
        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.RegistrationRejected) && r.Detail == """{"fields":["password"]}""");
        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.EmailVerificationFailed) && r.Detail == """{"reason":"unknown"}""");
        Assert.Contains(rows, r => r.EventType == nameof(AuditEventType.PasswordResetFailed) && r.Detail == """{"reason":"unknown"}""");
        Assert.Contains(rows, r => r.UserId == user.Id && r.EventType == nameof(AuditEventType.LoginFailed) && r.Detail == """{"reason":"wrong_password"}""");

        foreach (AuditLog row in rows)
        {
            string stored = string.Join("|", row.EventType, row.Detail, row.IpAddress, row.UserAgent, row.CorrelationId);
            Assert.All(secrets, secret => Assert.DoesNotContain(secret, stored, StringComparison.Ordinal));
        }

        IReadOnlyList<string> logs = api.Logs.Texts;
        Assert.All(secrets, secret => Assert.DoesNotContain(logs, line => line.Contains(secret, StringComparison.Ordinal)));
    }

    /// <summary>T17 audit MEDIUM-2: outside Development a disabled purge is reported at startup.</summary>
    [Fact]
    public async Task A_disabled_retention_purge_is_warned_about_outside_Development()
    {
        using Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        for (int i = 0; i < 50 && !api.Logs.Texts.Any(IsWarning); i++)
        {
            await Task.Delay(20);
        }

        Assert.Contains(api.Logs.Texts, IsWarning);

        static bool IsWarning(string line) => line.Contains("Retention:Enabled is false", StringComparison.Ordinal);
    }

    /// <summary>T09 review: an exception carrying secrets is logged through the real host only as a scrubbed copy.</summary>
    [Fact]
    public void An_exception_with_secrets_reaches_the_log_sinks_scrubbed()
    {
        const string marker = "scrub-probe-7f3a";
        ILogger logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("ScrubProbe");
        InvalidOperationException failure = new(marker + " password=" + FirstPassword + " token " + ForgedToken, new FormatException("Bearer " + WrongPassword));
        failure.Data["secret"] = SecondPassword;

        LogProbe(logger, failure, marker);

        string line = Assert.Single(api.Logs.Texts, t => t.Contains(marker, StringComparison.Ordinal) && t.Contains("Probe failure", StringComparison.Ordinal));
        Assert.Contains("System.InvalidOperationException", line, StringComparison.Ordinal);
        Assert.Contains("System.FormatException", line, StringComparison.Ordinal);
        foreach (string secret in new[] { FirstPassword, ForgedToken, WrongPassword, SecondPassword })
        {
            Assert.DoesNotContain(secret, line, StringComparison.Ordinal);
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Probe failure {Marker}")]
    private static partial void LogProbe(ILogger logger, Exception exception, string marker);

    private static void Expect(HttpStatusCode expected, HttpResponseMessage response) => Assert.Equal(expected, response.StatusCode);

    private static Task<HttpResponseMessage> PostAsync(Browser browser, string action, Dictionary<string, string> body) =>
        browser.SendAsync(HttpMethod.Post, "/api/v1/auth/" + action, configure: r => r.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"));

    private string LatestToken(string email)
    {
        EmailMessage message = api.Emails.Messages.Last(m => string.Equals(m.To, email, StringComparison.OrdinalIgnoreCase) && m.Body.Contains("#token=", StringComparison.Ordinal));
        int start = message.Body.IndexOf("#token=", StringComparison.Ordinal) + "#token=".Length;
        return new string([.. message.Body[start..].TakeWhile(c => char.IsLetterOrDigit(c) || c is '-' or '_')]);
    }

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }
}
