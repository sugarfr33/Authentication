using Auth.Api.Security;

namespace Auth.UnitTests.Security;

/// <summary>T20 shared-domain mode: the cookie Domain must be a safe registrable parent of the https auth host.</summary>
public class CookieDomainRulesTests
{
    [Theory]
    [InlineData("example.test", "https://auth.example.test", true)]
    [InlineData("auth.example.test", "https://auth.example.test", true)]
    [InlineData("example.co.uk", "https://login.example.co.uk", true)]
    [InlineData("example.test", "http://auth.example.test", false)]
    [InlineData("example.test", "https://auth.example.test.evil.test", false)]
    [InlineData("ample.test", "https://auth.example.test", false)]
    [InlineData("co.uk", "https://auth.example.co.uk", false)]
    [InlineData("com.au", "https://auth.example.com.au", false)]
    [InlineData("test", "https://auth.example.test", false)]
    [InlineData(".example.test", "https://auth.example.test", false)]
    [InlineData("example.test.", "https://auth.example.test", false)]
    [InlineData("Example.test", "https://auth.example.test", false)]
    [InlineData("127.0.0.1", "https://127.0.0.1", false)]
    [InlineData("example.123", "https://auth.example.123", false)]
    [InlineData("-bad.test", "https://auth.-bad.test", false)]
    [InlineData("example.test:443", "https://auth.example.test", false)]
    [InlineData("example.test", null, false)]
    public void Only_a_safe_parent_of_the_https_auth_host_is_allowed(string domain, string? issuer, bool allowed) =>
        Assert.Equal(allowed, CookieDomainRules.IsAllowed(domain, issuer));
}
