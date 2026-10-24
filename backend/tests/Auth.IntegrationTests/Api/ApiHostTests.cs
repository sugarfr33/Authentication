using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth.IntegrationTests.Api;

/// <summary>T09: the real Api host through WebApplicationFactory, in Production unless stated otherwise.</summary>
[Collection(ApiTestGroup.Name)]
public sealed partial class ApiHostTests(ApiFixture api)
{
    private static readonly string[] PrivateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    [Fact]
    public async Task Liveness_returns_200_Healthy()
    {
        using HttpClient client = api.CreateHttpsClient();

        HttpResponseMessage response = await client.GetAsync(new Uri("/health", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Readiness_checks_the_database_and_reveals_no_details_when_it_is_down()
    {
        using HttpClient client = api.CreateHttpsClient();
        HttpResponseMessage ready = await client.GetAsync(new Uri("/health/ready", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal("Healthy", await ready.Content.ReadAsStringAsync());

        await using WebApplicationFactory<Program> broken = api.Factory.WithWebHostBuilder(b =>
            b.UseSetting("ConnectionStrings:CentralAuth", api.MissingDatabaseConnectionString));
        using HttpClient brokenClient = api.CreateHttpsClient(broken);
        HttpResponseMessage down = await brokenClient.GetAsync(new Uri("/health/ready", UriKind.Relative));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, down.StatusCode);
        Assert.Equal("Unhealthy", await down.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await brokenClient.GetAsync(new Uri("/health", UriKind.Relative))).StatusCode);
    }

    [Theory]
    [InlineData("/health")]
    [InlineData("/health/ready")]
    [InlineData("/api/v1/does-not-exist")]
    [InlineData(ApiFixture.ThrowPath)]
    [InlineData("/.well-known/jwks.json")]
    public async Task Every_response_carries_the_security_headers(string path)
    {
        using HttpClient client = api.CreateHttpsClient();

        HttpResponseMessage response = await client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal("max-age=31536000; includeSubDomains", response.Header("Strict-Transport-Security"));
        Assert.Equal("nosniff", response.Header("X-Content-Type-Options"));
        Assert.Equal("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'", response.Header("Content-Security-Policy"));
        Assert.Equal("no-referrer", response.Header("Referrer-Policy"));
        Assert.Contains("camera=()", response.Header("Permissions-Policy"), StringComparison.Ordinal);
        Assert.Contains("geolocation=()", response.Header("Permissions-Policy"), StringComparison.Ordinal);
        Assert.Equal("DENY", response.Header("X-Frame-Options"));
        Assert.False(response.HasHeader("Server"));
        if (path.StartsWith("/.well-known", StringComparison.Ordinal))
        {
            Assert.Equal("public, max-age=300", response.Header("Cache-Control"));
        }
        else
        {
            Assert.Contains("no-store", response.Header("Cache-Control"), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Plain_http_is_redirected_to_https_and_gets_no_HSTS()
    {
        using HttpClient http = api.Factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://" + ApiFixture.Host), AllowAutoRedirect = false });

        HttpResponseMessage response = await http.GetAsync(new Uri("/health", UriKind.Relative));

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.Equal(new Uri("https://" + ApiFixture.Host + "/health"), response.Headers.Location);
        Assert.False(response.HasHeader("Strict-Transport-Security"));
    }

    [Fact]
    public async Task Unhandled_exception_gives_a_generic_ProblemDetails_without_message_or_stack_even_with_the_detail_flag_on()
    {
        using HttpClient client = api.CreateHttpsClient();

        HttpResponseMessage response = await client.GetAsync(new Uri(ApiFixture.ThrowPath, UriKind.Relative));
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain(ApiFixture.ThrowProbe, body, StringComparison.Ordinal);
        Assert.DoesNotContain("InvalidOperationException", body, StringComparison.Ordinal);
        Assert.DoesNotContain(" at ", body, StringComparison.Ordinal);
        Assert.DoesNotContain(".cs:line", body, StringComparison.Ordinal);
        using JsonDocument problem = JsonDocument.Parse(body);
        Assert.Equal(500, problem.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("An unexpected error occurred.", problem.RootElement.GetProperty("title").GetString());
        Assert.False(problem.RootElement.TryGetProperty("detail", out _));
        Assert.True(problem.RootElement.TryGetProperty("traceId", out _));
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    public async Task In_Development_details_appear_only_when_the_flag_is_explicitly_on(string flag, bool expectDetail)
    {
        await using WebApplicationFactory<Program> development = api.Factory.WithWebHostBuilder(b =>
        {
            b.UseEnvironment(Environments.Development);
            b.UseSetting("Errors:IncludeExceptionDetails", flag);
            b.ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?> { ["Errors:IncludeExceptionDetails"] = flag }));
        });
        using HttpClient client = api.CreateHttpsClient(development);

        HttpResponseMessage response = await client.GetAsync(new Uri(ApiFixture.ThrowPath, UriKind.Relative));
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(expectDetail, body.Contains(ApiFixture.ThrowProbe, StringComparison.Ordinal));
        Assert.DoesNotContain(".cs:line", body, StringComparison.Ordinal);
        Assert.False(response.HasHeader("Strict-Transport-Security"));
    }

    [Fact]
    public async Task Unknown_Host_header_is_rejected()
    {
        using HttpClient client = api.CreateHttpsClient();
        using HttpRequestMessage request = new(HttpMethod.Get, "/health");
        request.Headers.Host = "evil.example.test";

        HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("")]
    public void Production_refuses_to_start_with_unrestricted_AllowedHosts(string allowedHosts)
    {
        using WebApplicationFactory<Program> unrestricted = api.Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AllowedHosts", allowedHosts);
            b.ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?> { ["AllowedHosts"] = allowedHosts }));
        });

        Exception ex = Assert.ThrowsAny<Exception>(() => unrestricted.CreateClient());
        Assert.Contains("AllowedHosts", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task JWKS_is_unversioned_cacheable_and_contains_only_public_members()
    {
        using HttpClient client = api.CreateHttpsClient();

        HttpResponseMessage response = await client.GetAsync(new Uri("/.well-known/jwks.json", UriKind.Relative));
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/jwk-set+json", response.Content.Headers.ContentType?.MediaType);
        using JsonDocument jwks = JsonDocument.Parse(body);
        JsonElement key = Assert.Single(jwks.RootElement.GetProperty("keys").EnumerateArray());
        Assert.Equal(ApiFixture.SigningKid, key.GetProperty("kid").GetString());
        Assert.Equal("ES256", key.GetProperty("alg").GetString());
        Assert.Empty(key.EnumerateObject().Select(p => p.Name).Intersect(PrivateJwkMembers));
        Assert.DoesNotContain("PRIVATE KEY", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Logs_never_contain_passwords_tokens_cookies_or_authorization_values()
    {
        string[] probes = ["ProbePwd1", "ProbeTok2", "ProbeCode3", "ProbeBearer4", "ProbeCookie5", "ProbeKey6", "ProbePwd7", "ProbeRt8", "ProbeBearer9", "ProbePwd10"];
        int before = api.Logs.Events.Count;
        using HttpClient client = api.CreateHttpsClient();
        using HttpRequestMessage request = new(HttpMethod.Get, "/api/v1/missing?password=ProbePwd1&token=ProbeTok2&code=ProbeCode3");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer ProbeBearer4");
        request.Headers.TryAddWithoutValidation("Cookie", "__Host-access=ProbeCookie5");
        request.Headers.TryAddWithoutValidation("X-Api-Key", "ProbeKey6");

        ILogger probeLogger = api.Factory.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Probe");
        HttpResponseMessage response = await client.SendAsync(request);
        LogProbe(
            probeLogger,
            "ProbePwd7",
            "ProbeRt8",
            "Authorization: Bearer ProbeBearer9 and password=ProbePwd10");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        IReadOnlyList<string> texts = api.Logs.Texts;
        Assert.True(api.Logs.Events.Count > before);
        Assert.Contains(texts, t => t.Contains("/api/v1/missing", StringComparison.Ordinal));
        Assert.Contains(texts, t => t.Contains("[REDACTED]", StringComparison.Ordinal));
        Assert.All(probes, probe => Assert.DoesNotContain(texts, t => t.Contains(probe, StringComparison.Ordinal)));
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Probe login {Password} {RefreshToken} {Note}")]
    private static partial void LogProbe(ILogger logger, string password, string refreshToken, string note);
}
