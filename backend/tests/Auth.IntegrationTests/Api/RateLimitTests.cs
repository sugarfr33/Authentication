using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T11 rate limiting through the real pipeline. Each test uses its own app instance (fresh limiter state) with small
/// limits; /api/v1/__test/login is mapped to the Login kind by the fixture.
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class RateLimitTests(ApiFixture api)
{
    private const string Login = TestEndpoints.Prefix + "/login";

    [Fact]
    public async Task Per_IP_limit_returns_429_ProblemDetails_with_Retry_After()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 3, accountLimit: 100);
        using Browser browser = await ReadyBrowserAsync(app);

        HttpResponseMessage[] responses = new HttpResponseMessage[4];
        for (int i = 0; i < 4; i++)
        {
            responses[i] = await PostLoginAsync(browser, "user" + i + "@example.test");
        }

        Assert.All(responses[..3], r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        HttpResponseMessage limited = responses[3];
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);
        Assert.InRange(int.Parse(limited.Header("Retry-After"), CultureInfo.InvariantCulture), 1, 300);
    }

    [Fact]
    public async Task Per_account_limit_applies_to_one_normalized_email_only()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 100, accountLimit: 2);
        using Browser browser = await ReadyBrowserAsync(app);

        HttpResponseMessage first = await PostLoginAsync(browser, "victim@example.test");
        HttpResponseMessage second = await PostLoginAsync(browser, "  VICTIM@Example.TEST ");
        HttpResponseMessage third = await PostLoginAsync(browser, "Victim@example.test");
        HttpResponseMessage other = await PostLoginAsync(browser, "someone.else@example.test");

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.True(third.HasHeader("Retry-After"));
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task Spoofed_X_Forwarded_For_does_not_change_the_partition_by_default()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 2, accountLimit: 100);
        using Browser browser = await ReadyBrowserAsync(app);

        HttpStatusCode[] statuses = new HttpStatusCode[3];
        for (int i = 0; i < 3; i++)
        {
            string spoofed = "198.51.100." + (i + 1);
            statuses[i] = (await PostLoginAsync(browser, "u" + i + "@example.test", r => r.Headers.TryAddWithoutValidation("X-Forwarded-For", spoofed))).StatusCode;
        }

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], statuses);
    }

    [Fact]
    public async Task X_Forwarded_For_is_honored_only_from_a_configured_known_proxy()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 2, accountLimit: 100, new() { ["ForwardedHeaders:KnownProxies:0"] = ApiFixture.TestRemoteIp });
        using Browser browser = await ReadyBrowserAsync(app);

        for (int i = 0; i < 4; i++)
        {
            string client = "198.51.100." + (i + 1);
            HttpResponseMessage response = await PostLoginAsync(browser, "p" + i + "@example.test", r => r.Headers.TryAddWithoutValidation("X-Forwarded-For", client));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task The_body_reaches_the_endpoint_intact()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 100, accountLimit: 1);
        using Browser browser = await ReadyBrowserAsync(app);
        string small = JsonSerializer.Serialize(new { email = "small@example.test", padding = new string('x', 10_000) });

        HttpResponseMessage first = await PostJsonAsync(browser, small);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using JsonDocument echoed = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        Assert.Equal(small.Length, echoed.RootElement.GetProperty("length").GetInt32());
        Assert.Equal(HttpStatusCode.TooManyRequests, (await PostJsonAsync(browser, small)).StatusCode);
    }

    /// <summary>Audit MEDIUM-1/3: a padded body can no longer skip the account key; it is refused with 413 instead.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Bodies_over_the_cap_get_413_with_or_without_Content_Length(bool sendLength)
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 100, accountLimit: 100);
        using Browser browser = await ReadyBrowserAsync(app);
        string big = JsonSerializer.Serialize(new { email = "big@example.test", padding = new string('x', 20_000) });

        HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, Login, configure: request =>
        {
            byte[] bytes = Encoding.UTF8.GetBytes(big);
            request.Content = sendLength ? new ByteArrayContent(bytes) : new StreamContent(new UnknownLengthStream(bytes));
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        });

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>Audit LOW-2: the per-IP limit counts the request before the body is read.</summary>
    [Fact]
    public async Task The_IP_limit_counts_before_the_body_is_read()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 2, accountLimit: 100);
        using Browser browser = await ReadyBrowserAsync(app);
        string big = JsonSerializer.Serialize(new { email = "x@example.test", padding = new string('x', 20_000) });

        HttpStatusCode[] statuses = [(await PostJsonAsync(browser, big)).StatusCode, (await PostJsonAsync(browser, big)).StatusCode, (await PostJsonAsync(browser, big)).StatusCode];

        Assert.Equal([HttpStatusCode.RequestEntityTooLarge, HttpStatusCode.RequestEntityTooLarge, HttpStatusCode.TooManyRequests], statuses);
    }

    /// <summary>Audit MEDIUM-2: BOM-prefixed bodies count against the same account; non-utf-8 charsets get 415.</summary>
    [Fact]
    public async Task BOM_bodies_share_the_account_and_non_utf8_charsets_get_415()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 100, accountLimit: 2);
        using Browser browser = await ReadyBrowserAsync(app);
        string json = JsonSerializer.Serialize(new { email = "bom@example.test", password = "irrelevant-123" });

        HttpResponseMessage plain = await PostJsonAsync(browser, json);
        HttpResponseMessage withBom = await PostBytesAsync(browser, [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(json)], "application/json");
        HttpResponseMessage third = await PostBytesAsync(browser, [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(json)], "application/json");
        HttpResponseMessage utf16 = await PostBytesAsync(browser, Encoding.Unicode.GetBytes("""{"email":"other@example.test"}"""), "application/json; charset=utf-16");

        Assert.Equal(HttpStatusCode.OK, plain.StatusCode);
        Assert.Equal(HttpStatusCode.OK, withBom.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, utf16.StatusCode);
    }

    /// <summary>Audit LOW-3: a loopback/private peer sending X-Forwarded-For without KnownProxies logs one warning.</summary>
    [Fact]
    public async Task An_unconfigured_proxy_is_reported_once_as_a_warning()
    {
        using Browser browser = new(api.Factory);
        await browser.SendAsync(HttpMethod.Get, TestEndpoints.Prefix + "/ping", sendOrigin: false, sendXsrf: false, configure: r => r.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100.9"));

        Assert.Contains(api.Logs.Texts, t => t.Contains("ForwardedHeaders:KnownProxies is empty", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Paths_that_are_not_auth_operations_are_never_limited()
    {
        await using WebApplicationFactory<Program> app = WithLimits(ipLimit: 1, accountLimit: 1);
        using Browser browser = new(app);

        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(TestEndpoints.Prefix + "/ping")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/echo")).StatusCode);
        }
    }

    [Fact]
    public async Task Exhausted_hashing_capacity_returns_503_with_Retry_After()
    {
        using Browser browser = await ReadyBrowserAsync(api.Factory);

        HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/busy");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("1", response.Header("Retry-After"));
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    private static async Task<Browser> ReadyBrowserAsync(WebApplicationFactory<Program> app)
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return browser;
    }

    private static Task<HttpResponseMessage> PostLoginAsync(Browser browser, string email, Action<HttpRequestMessage>? configure = null) =>
        PostJsonAsync(browser, JsonSerializer.Serialize(new { email, password = "irrelevant-123" }), configure);

    private static Task<HttpResponseMessage> PostJsonAsync(Browser browser, string json, Action<HttpRequestMessage>? configure = null) =>
        browser.SendAsync(HttpMethod.Post, Login, configure: request =>
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            configure?.Invoke(request);
        });

    private static Task<HttpResponseMessage> PostBytesAsync(Browser browser, byte[] body, string contentType) =>
        browser.SendAsync(HttpMethod.Post, Login, configure: request =>
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        });

    private WebApplicationFactory<Program> WithLimits(int ipLimit, int accountLimit, Dictionary<string, string?>? extra = null)
    {
        Dictionary<string, string?> settings = new()
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = ipLimit.ToString(CultureInfo.InvariantCulture),
            ["RateLimiting:Policies:Login:PerIp:Window"] = "00:05:00",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = accountLimit.ToString(CultureInfo.InvariantCulture),
            ["RateLimiting:Policies:Login:PerAccount:Window"] = "00:05:00",
        };
        foreach (KeyValuePair<string, string?> pair in extra ?? [])
        {
            settings[pair.Key] = pair.Value;
        }

        return api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
        });
    }

    /// <summary>A readable stream that does not report its length, so the request is sent chunked.</summary>
    private sealed class UnknownLengthStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }
}
