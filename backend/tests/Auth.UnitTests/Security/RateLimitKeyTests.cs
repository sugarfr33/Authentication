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
    [InlineData("""["email","a@example.test"]""")]
    [InlineData("""not json""")]
    [InlineData("")]
    public void No_email_field_or_no_object_gives_no_account_key(string json)
    {
        Assert.Null(Find(json));
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

    private static string? Find(string json) => AccountKeyMiddleware.FindEmail(Encoding.UTF8.GetBytes(json));
}
