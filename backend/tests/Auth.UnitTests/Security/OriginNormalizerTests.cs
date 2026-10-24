using Auth.Services.ClientApplications;

namespace Auth.UnitTests.Security;

public class OriginNormalizerTests
{
    [Theory]
    [InlineData("https://app.example.com", "https://app.example.com")]
    [InlineData("https://App.Example.COM/", "https://app.example.com")]
    [InlineData("https://app.example.com:8443", "https://app.example.com:8443")]
    [InlineData("https://app.example.com:443", "https://app.example.com")]
    [InlineData("http://localhost:5173", "http://localhost:5173")]
    public void Exact_origins_are_normalized(string input, string expected)
    {
        Assert.True(OriginNormalizer.TryNormalize(input, out string origin));
        Assert.Equal(expected, origin);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("null")]
    [InlineData("https://*.example.com")]
    [InlineData("https://app.example.com/path")]
    [InlineData("https://app.example.com?x=1")]
    [InlineData("https://user:pw@app.example.com")]
    [InlineData("ftp://app.example.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("app.example.com")]
    public void Anything_but_an_exact_http_origin_is_rejected(string? input)
    {
        Assert.False(OriginNormalizer.TryNormalize(input, out _));
    }

    [Theory]
    [InlineData("https://app.example.com/settings?tab=1", "https://app.example.com")]
    [InlineData("http://localhost:5173/x", "http://localhost:5173")]
    public void Referer_origin_is_extracted(string referer, string expected)
    {
        Assert.True(OriginNormalizer.TryGetOrigin(referer, out string origin));
        Assert.Equal(expected, origin);
    }

    [Theory]
    [InlineData("https://app.example.com", true)]
    [InlineData("http://localhost:5173", true)]
    [InlineData("http://127.0.0.1:8080", true)]
    [InlineData("http://[::1]:5000", true)]
    [InlineData("http://app.example.com", false)]
    [InlineData("http://localhost.evil.com", false)]
    public void Https_is_required_except_for_loopback_hosts(string input, bool accepted)
    {
        Assert.Equal(accepted, OriginNormalizer.TryNormalize(input, requireHttps: true, out _));
        Assert.True(OriginNormalizer.TryNormalize(input, requireHttps: false, out _));
    }
}
