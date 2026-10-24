using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Auth.IntegrationTests.Api;

/// <summary>T10 review hardening (T11 part 1): startup guards and https-only origins outside Development.</summary>
[Collection(ApiTestGroup.Name)]
public sealed class BrowserProtectionHardeningTests(ApiFixture api)
{
    private const string Echo = TestEndpoints.Prefix + "/echo";

    [Fact]
    public void Production_refuses_to_start_with_AllowMissingOrigin()
    {
        using WebApplicationFactory<Program> factory = WithSettings(new() { ["BrowserProtection:AllowMissingOrigin"] = "true" });

        Exception ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("AllowMissingOrigin", ex.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://login.example.test")]
    [InlineData("https://*.example.test")]
    public void Production_refuses_to_start_with_an_insecure_or_wildcard_trusted_origin(string origin)
    {
        using WebApplicationFactory<Program> factory = WithSettings(new() { ["BrowserProtection:TrustedOrigins:0"] = origin });

        Exception ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("TrustedOrigins", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Production_accepts_an_http_loopback_trusted_origin()
    {
        await using WebApplicationFactory<Program> factory = WithSettings(new() { ["BrowserProtection:TrustedOrigins:0"] = "http://localhost:4200" });
        using Browser browser = new(factory, "http://localhost:4200");
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");

        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(HttpMethod.Post, Echo)).StatusCode);
    }

    [Fact]
    public async Task Production_ignores_http_application_origins_except_loopback()
    {
        using HttpClient client = api.CreateHttpsClient();

        Assert.Equal(string.Empty, (await SimpleGetAsync(client, ApiFixture.InsecureOrigin)).Header("Access-Control-Allow-Origin"));
        Assert.Equal(ApiFixture.LoopbackOrigin, (await SimpleGetAsync(client, ApiFixture.LoopbackOrigin)).Header("Access-Control-Allow-Origin"));

        using Browser insecure = new(api.Factory, ApiFixture.InsecureOrigin);
        await insecure.GetAsync(TestEndpoints.Prefix + "/ping");
        Assert.Equal(HttpStatusCode.Forbidden, (await insecure.SendAsync(HttpMethod.Post, Echo)).StatusCode);
    }

    [Fact]
    public async Task Development_accepts_http_application_origins()
    {
        await using WebApplicationFactory<Program> development = WithSettings([], Environments.Development);
        using HttpClient client = api.CreateHttpsClient(development);

        Assert.Equal(ApiFixture.InsecureOrigin, (await SimpleGetAsync(client, ApiFixture.InsecureOrigin)).Header("Access-Control-Allow-Origin"));
    }

    private static async Task<HttpResponseMessage> SimpleGetAsync(HttpClient client, string origin)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, TestEndpoints.Prefix + "/ping");
        request.Headers.TryAddWithoutValidation("Origin", origin);
        return await client.SendAsync(request);
    }

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> settings, string? environment = null) => api.Factory.WithWebHostBuilder(builder =>
    {
        if (environment is not null)
        {
            builder.UseEnvironment(environment);
        }

        foreach (KeyValuePair<string, string?> setting in settings)
        {
            builder.UseSetting(setting.Key, setting.Value);
        }

        builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
    });
}
