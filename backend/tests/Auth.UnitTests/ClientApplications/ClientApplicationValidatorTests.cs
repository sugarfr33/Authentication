using Auth.Contracts.Requests;
using Auth.Services.ClientApplications;

namespace Auth.UnitTests.ClientApplications;

/// <summary>T18: strict validation of client application settings (origins, redirect URIs, audience, caps).</summary>
public class ClientApplicationValidatorTests
{
    private const string DefaultAudience = "https://auth.example.test";

    private static readonly ClientApplicationValidator Production = new(requireHttps: true, DefaultAudience);
    private static readonly ClientApplicationValidator Development = new(requireHttps: false, DefaultAudience);

    [Fact]
    public void A_valid_request_is_normalized()
    {
        (ValidClientApplication? valid, IReadOnlyDictionary<string, string[]> errors) = Production.Validate(Request(
            origins: ["https://App.Example.com:8443/", "https://app.example.com:8443"],
            redirects: ["https://App.Example.com/callback?tenant=1"]));

        Assert.Empty(errors);
        Assert.Equal(["https://app.example.com:8443"], valid!.AllowedOrigins);
        Assert.Equal(["https://app.example.com/callback?tenant=1"], valid.RedirectUris);
        Assert.Equal("orders-spa", valid.ClientId);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("null")]
    [InlineData("https://*.example.com")]
    [InlineData("https://app.example.com/path")]
    [InlineData("https://app.example.com?x=1")]
    [InlineData("https://app.example.com#fragment")]
    [InlineData("https://user@app.example.com")]
    [InlineData("http://app.example.com")]
    [InlineData("http://localhost:5173")]
    [InlineData("javascript:alert(1)")]
    [InlineData("ftp://app.example.com")]
    [InlineData("app.example.com")]
    [InlineData("https://app.exa mple.com")]
    public void Bad_origins_are_refused_in_production(string origin)
    {
        (ValidClientApplication? valid, IReadOnlyDictionary<string, string[]> errors) = Production.Validate(Request(origins: [origin]));

        Assert.Null(valid);
        Assert.True(errors.ContainsKey("allowedOrigins"));
        Assert.DoesNotContain(errors["allowedOrigins"], m => m.Contains(origin, StringComparison.Ordinal) && origin.Length > 5);
    }

    [Theory]
    [InlineData("http://localhost:5173", true)]
    [InlineData("http://127.0.0.1:5173", true)]
    [InlineData("http://app.example.com", false)]
    public void Development_allows_plain_http_only_for_loopback(string origin, bool allowed) =>
        Assert.Equal(allowed, Development.Validate(Request(origins: [origin])).Valid is not null);

    [Theory]
    [InlineData("https://app.example.com/cb#x")]
    [InlineData("https://app.example.com/*")]
    [InlineData("https://*.example.com/cb")]
    [InlineData("//evil.example/cb")]
    [InlineData("/cb")]
    [InlineData("http://app.example.com/cb")]
    [InlineData("https://user:pass@app.example.com/cb")]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://app.example.com/a\\b")]
    public void Bad_redirect_uris_are_refused(string redirect)
    {
        Assert.Null(Production.Validate(Request(redirects: [redirect])).Valid);
        Assert.Null(Production.Validate(Request(postLogout: [redirect])).Valid);
    }

    [Theory]
    [InlineData("https://auth.example.test")]
    [InlineData("https://AUTH.example.test/")]
    [InlineData("orders")]
    [InlineData("")]
    [InlineData("api://orders#x")]
    [InlineData("api://*")]
    public void Bad_audiences_are_refused_including_this_APIs_own(string audience) =>
        Assert.True(Production.Validate(Request(audience: audience)).Errors.ContainsKey("audience"));

    [Theory]
    [InlineData("ab")]
    [InlineData("Orders")]
    [InlineData("-orders")]
    [InlineData("orders spa")]
    [InlineData("orders/spa")]
    public void Bad_client_ids_are_refused(string clientId) =>
        Assert.True(Production.Validate(Request(clientId: clientId)).Errors.ContainsKey("clientId"));

    [Fact]
    public void Lists_and_values_are_capped()
    {
        string[] eleven = [.. Enumerable.Range(0, 11).Select(i => "https://app" + i + ".example.com")];
        string longRedirect = "https://app.example.com/" + new string('a', 600);

        Assert.True(Production.Validate(Request(origins: eleven)).Errors.ContainsKey("allowedOrigins"));
        Assert.True(Production.Validate(Request(redirects: [longRedirect])).Errors.ContainsKey("redirectUris"));
        Assert.True(Production.Validate(Request(name: new string('n', 129))).Errors.ContainsKey("name"));
        Assert.True(Production.Validate(Request(audience: "api://" + new string('a', 260))).Errors.ContainsKey("audience"));
    }

    private static ClientApplicationRequest Request(
        string clientId = "orders-spa",
        string name = "Orders",
        string audience = "api://orders",
        string[]? origins = null,
        string[]? redirects = null,
        string[]? postLogout = null) =>
        new(clientId, name, audience, origins ?? ["https://orders.example.com"], redirects ?? ["https://orders.example.com/callback"], postLogout ?? []);
}
