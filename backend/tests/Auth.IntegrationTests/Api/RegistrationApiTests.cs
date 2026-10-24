using System.Net;
using System.Text;
using System.Text.Json;
using Auth.Contracts.Requests;
using Auth.Services.Accounts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T12 through the real pipeline: POST /api/v1/auth/register and /verify-email with origin, antiforgery, rate limits
/// and ProblemDetails. The register per-IP limit is raised for this class so the tests do not throttle each other.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class RegistrationApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Register = "/api/v1/auth/register";
    private const string VerifyEmail = "/api/v1/auth/verify-email";
    private const string Password = "violet-canyon-7319";

    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        app = WithSettings(new()
        {
            ["RateLimiting:Policies:Register:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Register:PerAccount:PermitLimit"] = "1000",
        });
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task Register_then_verify_once_through_the_pipeline()
    {
        using Browser browser = await ReadyBrowserAsync(app);
        string email = UniqueEmail();

        HttpResponseMessage registered = await PostJsonAsync(browser, Register, RegisterJson(email));
        string token = TokenFor(email);
        HttpResponseMessage verified = await PostJsonAsync(browser, VerifyEmail, JsonSerializer.Serialize(new { token }));
        HttpResponseMessage reused = await PostJsonAsync(browser, VerifyEmail, JsonSerializer.Serialize(new { token }));

        Assert.Equal(HttpStatusCode.Accepted, registered.StatusCode);
        Assert.Contains(AccountEndpointsMessage, await registered.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NoContent, verified.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, reused.StatusCode);
        Assert.Equal("application/problem+json", reused.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Duplicate_email_answers_are_byte_identical_to_a_new_sign_up()
    {
        using Browser browser = await ReadyBrowserAsync(app);
        string email = UniqueEmail();

        (HttpStatusCode Status, string? Type, string Body) fresh = await SnapshotAsync(await PostJsonAsync(browser, Register, RegisterJson(email)));
        (HttpStatusCode Status, string? Type, string Body) unverifiedDuplicate = await SnapshotAsync(await PostJsonAsync(browser, Register, RegisterJson(" " + email.ToUpperInvariant())));
        string token = TokenFor(email, latest: true);
        Assert.Equal(HttpStatusCode.NoContent, (await PostJsonAsync(browser, VerifyEmail, JsonSerializer.Serialize(new { token }))).StatusCode);
        (HttpStatusCode Status, string? Type, string Body) verifiedDuplicate = await SnapshotAsync(await PostJsonAsync(browser, Register, RegisterJson(email, "other-password-4821")));

        Assert.Equal(HttpStatusCode.Accepted, fresh.Status);
        Assert.Equal(fresh, unverifiedDuplicate);
        Assert.Equal(fresh, verifiedDuplicate);
    }

    [Fact]
    public async Task Invalid_input_is_a_ValidationProblem_and_creates_nothing()
    {
        using Browser browser = await ReadyBrowserAsync(app);
        string email = "bad@@example";

        HttpResponseMessage response = await PostJsonAsync(browser, Register, JsonSerializer.Serialize(new { email, password = "password", displayName = "" }));
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using JsonDocument problem = JsonDocument.Parse(body);
        JsonElement errors = problem.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("email", out _));
        Assert.True(errors.TryGetProperty("password", out _));
        Assert.True(errors.TryGetProperty("displayName", out _));
        Assert.DoesNotContain(api.Emails.Messages, m => m.To == email);
    }

    [Theory]
    [InlineData("{\"email\":")]
    [InlineData("null")]
    [InlineData("[]")]
    public async Task Malformed_bodies_get_a_400_ProblemDetails(string json)
    {
        using Browser browser = await ReadyBrowserAsync(app);

        HttpResponseMessage response = await PostJsonAsync(browser, Register, json);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Form_bodies_are_refused_with_415()
    {
        using Browser browser = await ReadyBrowserAsync(app);
        string email = UniqueEmail();

        HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, Register, configure: request =>
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["email"] = email, ["password"] = Password, ["displayName"] = "Form" }));

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.DoesNotContain(api.Emails.Messages, m => m.To == email);
    }

    [Fact]
    public async Task Register_without_the_antiforgery_token_is_refused()
    {
        using Browser browser = await ReadyBrowserAsync(app);
        string email = UniqueEmail();

        HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, Register, sendXsrf: false, configure: request =>
            request.Content = new StringContent(RegisterJson(email), Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(api.Emails.Messages, m => m.To == email);
    }

    [Fact]
    public async Task Tokens_and_passwords_never_reach_the_logs()
    {
        using Browser browser = await ReadyBrowserAsync(app);
        string email = UniqueEmail();
        await PostJsonAsync(browser, Register, RegisterJson(email));
        string token = TokenFor(email);
        await PostJsonAsync(browser, VerifyEmail, JsonSerializer.Serialize(new { token }));

        Assert.DoesNotContain(api.Logs.Texts, t => t.Contains(token, StringComparison.Ordinal) || t.Contains(Password, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Register_is_limited_per_account_whether_or_not_the_account_exists()
    {
        await using WebApplicationFactory<Program> limited = WithSettings(new()
        {
            ["RateLimiting:Policies:Register:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Register:PerAccount:PermitLimit"] = "2",
        });
        using Browser browser = await ReadyBrowserAsync(limited);
        string email = UniqueEmail();

        HttpStatusCode[] statuses = new HttpStatusCode[3];
        for (int i = 0; i < statuses.Length; i++)
        {
            statuses[i] = (await PostJsonAsync(browser, Register, RegisterJson(i == 1 ? email.ToUpperInvariant() : email))).StatusCode;
        }

        Assert.Equal([HttpStatusCode.Accepted, HttpStatusCode.Accepted, HttpStatusCode.TooManyRequests], statuses);
    }

    private static string AccountEndpointsMessage => "Check your inbox";

    private static string UniqueEmail() => "api-reg-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";

    private static string RegisterJson(string email, string password = Password) =>
        JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = password, ["displayName"] = "Api Tester" });

    private static async Task<(HttpStatusCode Status, string? Type, string Body)> SnapshotAsync(HttpResponseMessage response) =>
        (response.StatusCode, response.Content.Headers.ContentType?.ToString(), await response.Content.ReadAsStringAsync());

    private static async Task<Browser> ReadyBrowserAsync(WebApplicationFactory<Program> factory)
    {
        Browser browser = new(factory);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return browser;
    }

    private static Task<HttpResponseMessage> PostJsonAsync(Browser browser, string path, string json) =>
        browser.SendAsync(HttpMethod.Post, path, configure: request => request.Content = new StringContent(json, Encoding.UTF8, "application/json"));

    private string TokenFor(string email, bool latest = false)
    {
        List<EmailMessage> messages = api.Emails.Messages.Where(m => string.Equals(m.To.Trim(), email.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
        EmailMessage message = latest ? messages[^1] : Assert.Single(messages);
        const string marker = "#token=";
        int start = message.Body.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, "The email holds no verification link.");
        return new string(message.Body[(start + marker.Length)..].TakeWhile(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray());
    }

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> settings) =>
        api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        });
}
