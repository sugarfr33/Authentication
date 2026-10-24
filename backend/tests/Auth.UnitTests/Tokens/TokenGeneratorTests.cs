using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Auth.Services.Tokens;

namespace Auth.UnitTests.Tokens;

public class TokenGeneratorTests
{
    private readonly TokenGenerator generator = new();

    [Fact]
    public void Token_is_256_bits_base64url_and_its_hash_is_SHA256_of_the_text()
    {
        GeneratedToken token = generator.Generate();

        Assert.Matches("^[A-Za-z0-9_-]{43}$", token.Value);
        Assert.Equal(32, Base64Url.DecodeFromChars(token.Value).Length);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(token.Value)), token.Hash);
        Assert.Equal(token.Hash, generator.Hash(token.Value));
    }

    [Fact]
    public void Tokens_do_not_repeat()
    {
        HashSet<string> seen = [];
        for (int i = 0; i < 10_000; i++)
        {
            Assert.True(seen.Add(generator.Generate().Value));
        }
    }

    [Fact]
    public void Refresh_defaults_are_14_days_sliding_30_days_absolute_10_seconds_grace()
    {
        RefreshTokenOptions options = new RefreshTokenOptions().Validated();

        Assert.Equal(TimeSpan.FromDays(14), options.SlidingLifetime);
        Assert.Equal(TimeSpan.FromDays(30), options.AbsoluteLifetime);
        Assert.Equal(TimeSpan.FromSeconds(10), options.ReuseGraceWindow);
        Assert.Throws<ArgumentOutOfRangeException>(() => new RefreshTokenOptions { AbsoluteLifetime = TimeSpan.FromDays(7) }.Validated());
        Assert.Throws<ArgumentOutOfRangeException>(() => new RefreshTokenOptions { ReuseGraceWindow = TimeSpan.FromMinutes(5) }.Validated());
    }
}
