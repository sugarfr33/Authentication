using System.Net;
using System.Text;
using Auth.Api.RateLimiting;

namespace Auth.UnitTests.Security;

/// <summary>T11 review: account keys mirror System.Text.Json binding; IPv6 clients are partitioned per /64.</summary>
public class RateLimitKeyTests
{
    private const string Ambiguous = AccountKeyMiddleware.AmbiguousAccount;

    [Theory]
    [InlineData("""{"email":"Ada@Example.test"}""")]
    [InlineData("""{"Email":"Ada@Example.test"}""")]
    [InlineData("""{"EMAIL":"Ada@Example.test"}""")]
    [InlineData("""{"eMail":"  ada@example.TEST  "}""")]
    [InlineData("""{"password":"x","eMaIl":"ada@example.test","other":{"email":"nested@example.test"}}""")]
    public void Property_name_matches_case_insensitively_like_the_binder(string json)
    {
        Assert.Equal("ADA@EXAMPLE.TEST", Find(json));
    }

    [Theory]
    [InlineData("""{"email":"a@example.test","email":"b@example.test"}""")]
    [InlineData("""{"email":"b@example.test","Email":"a@example.test"}""")]
    [InlineData("""{"EMAIL":"x@example.test","password":"p","email":"x@example.test"}""")]
    public void Duplicate_email_keys_in_any_order_share_the_ambiguous_bucket(string json)
    {
        Assert.Equal(Ambiguous, Find(json));
    }

    [Theory]
    [InlineData("""{"email":123}""")]
    [InlineData("""{"email":null}""")]
    [InlineData("""{"email":["a@example.test"]}""")]
    [InlineData("""{"email":{"value":"a@example.test"}}""")]
    [InlineData("""{"email":"   "}""")]
    public void Non_string_or_empty_email_shares_the_ambiguous_bucket(string json)
    {
        Assert.Equal(Ambiguous, Find(json));
    }

    [Theory]
    [InlineData("""{"username":"a@example.test"}""")]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_body_or_object_without_email_gives_no_account_key(string json)
    {
        Assert.Null(Find(json));
    }

    /// <summary>Audit MEDIUM-2 / LOW-1: anything the reader cannot parse must not escape the per-account limit.</summary>
    [Theory]
    [InlineData("""["email","a@example.test"]""")]
    [InlineData("""not json""")]
    [InlineData("{\"email\":\"a@example.test\"")]
    public void Unparsable_or_non_object_bodies_share_the_ambiguous_bucket(string json)
    {
        Assert.Equal(Ambiguous, Find(json));
    }

    [Fact]
    public void A_UTF8_BOM_is_skipped_like_the_binder_does()
    {
        byte[] body = [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("""{"email":"bom@example.test"}""")];

        Assert.Equal("BOM@EXAMPLE.TEST", AccountKeyMiddleware.FindEmail(body));
    }

    [Fact]
    public void Nesting_deeper_than_8_still_parses_up_to_the_binder_depth()
    {
        string deep = """{"email":"deep@example.test","pad":""" + new string('[', 9) + "1" + new string(']', 9) + "}";
        string tooDeep = """{"email":"deep@example.test","pad":""" + new string('[', 80) + "1" + new string(']', 80) + "}";

        Assert.Equal("DEEP@EXAMPLE.TEST", Find(deep));
        Assert.Equal(Ambiguous, Find(tooDeep));
    }

    [Fact]
    public void Invalid_UTF8_inside_the_email_string_shares_the_ambiguous_bucket()
    {
        byte[] body = [.. Encoding.UTF8.GetBytes("{\"email\":\"a"), 0xC3, 0x28, .. Encoding.UTF8.GetBytes("@example.test\"}")];

        Assert.Equal(Ambiguous, AccountKeyMiddleware.FindEmail(body));
    }

    [Theory]
    [InlineData("application/json", true)]
    [InlineData("application/json; charset=utf-8", true)]
    [InlineData("application/json; charset=UTF8", true)]
    [InlineData("application/json; charset=\"utf-8\"", true)]
    [InlineData("application/json; charset=utf-16", false)]
    [InlineData("application/json; charset=iso-8859-1", false)]
    public void Only_utf8_charsets_are_accepted(string contentType, bool accepted)
    {
        Assert.Equal(accepted, AccountKeyMiddleware.IsUtf8Charset(contentType));
    }

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]
    [InlineData("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:3::1", "2001:db8:1:3::/64")]
    public void IPv4_is_per_address_and_IPv6_is_per_64(string address, string expected)
    {
        Assert.Equal(expected, AuthRateLimiting.ClientPartitionKey(IPAddress.Parse(address)));
    }

    [Fact]
    public void Missing_address_has_a_fixed_key()
    {
        Assert.Equal("unknown", AuthRateLimiting.ClientPartitionKey(null));
    }

    /// <summary>T15: routes with an id are matched by prefix; exact paths still win and look-alike paths do not match.</summary>
    [Theory]
    [InlineData("/api/v1/auth/sessions", AuthRateLimitKind.Sessions)]
    [InlineData("/api/v1/auth/sessions/", AuthRateLimitKind.Sessions)]
    [InlineData("/API/v1/Auth/Sessions/3f2b8c1e-0000-4000-8000-000000000000", AuthRateLimitKind.Sessions)]
    [InlineData("/api/v1/auth/sessionsX", null)]
    [InlineData("/api/v1/auth/login", AuthRateLimitKind.Login)]
    [InlineData("/api/v1/auth/me", null)]
    public void Paths_resolve_exactly_or_by_prefix(string path, AuthRateLimitKind? expected)
    {
        Assert.Equal(expected, new AuthRateLimitOptions().Resolve(path));
    }

    private static string? Find(string json) => AccountKeyMiddleware.FindEmail(Encoding.UTF8.GetBytes(json));
}
