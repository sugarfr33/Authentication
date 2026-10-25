using Auth.Api.RateLimiting;
using Auth.Services.ClientApplications;
using Auth.Services.OAuth;

namespace Auth.UnitTests.OAuth;

/// <summary>T19: S256 verification (vector computed independently with Python hashlib), reserved role names, per-client rate-limit key.</summary>
public class PkceAndKeysTests
{
    [Fact]
    public void An_independently_computed_S256_vector_verifies()
    {
        // base64url(sha256(b"dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKQ")) computed outside .NET.
        Assert.True(OAuthService.VerifierMatches("dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKQ", "DsBXq9E2fBCRJUhGT6UXeHBt8EVGWP5PUGmVXidcjCI"));
        Assert.False(OAuthService.VerifierMatches("dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKR", "DsBXq9E2fBCRJUhGT6UXeHBt8EVGWP5PUGmVXidcjCI"));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("has space dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKQ")]
    [InlineData("DsBXq9E2fBCRJUhGT6UXeHBt8EVGWP5PUGmVXidcjCI")]
    public void Malformed_or_plain_verifiers_never_match(string verifier) =>
        Assert.False(OAuthService.VerifierMatches(verifier, "DsBXq9E2fBCRJUhGT6UXeHBt8EVGWP5PUGmVXidcjCI"));

    [Theory]
    [InlineData("app:orders:Admin", true)]
    [InlineData("APP:x", true)]
    [InlineData(" app:x", true)]
    [InlineData("Admin", false)]
    [InlineData("application", false)]
    public void Global_role_names_starting_with_app_are_reserved(string name, bool reserved) =>
        Assert.Equal(reserved, RoleNames.IsReservedForApplications(name));

    [Theory]
    [InlineData("grant_type=authorization_code&client_id=orders-spa", "client:orders-spa")]
    [InlineData("client_id=a&client_id=b", "(ambiguous)")]
    [InlineData("grant_type=authorization_code", "(ambiguous)")]
    public void The_token_endpoint_is_limited_per_client_id(string form, string key) =>
        Assert.Equal(key, AccountKeyMiddleware.FindClientId(System.Text.Encoding.UTF8.GetBytes(form)));
}
