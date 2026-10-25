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
    [InlineData("orders-spa")]
    [InlineData("Orders-SPA")]
    [InlineData("ORDERS-SPA")]
    public void Every_letter_case_of_a_client_id_shares_one_rate_limit_bucket(string clientId) =>
        Assert.Equal("client:orders-spa", ClientRateLimit.Key(clientId));

    /// <summary>T19 audit L1: a .NET $ also matches before a final newline; the anchors are \z.</summary>
    [Fact]
    public void A_verifier_with_a_trailing_newline_never_matches()
    {
        const string Verifier = "dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKQ";
        string challenge = OAuthService.Base64Url(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(Verifier + "\n")));

        Assert.False(OAuthService.VerifierMatches(Verifier + "\n", challenge));
    }
}
