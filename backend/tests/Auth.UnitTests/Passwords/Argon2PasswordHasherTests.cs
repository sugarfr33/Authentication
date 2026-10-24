using Auth.Services.Passwords;
using Konscious.Security.Cryptography;

namespace Auth.UnitTests.Passwords;

public class Argon2PasswordHasherTests
{
    /// <summary>Cheap parameters so the suite stays fast. Production defaults are covered by one test below.</summary>
    internal static readonly PasswordHashingOptions FastOptions = new() { MemorySizeKiB = 1024, Iterations = 1, Parallelism = 1 };

    private const string Password = "violet-canyon-7319";

    private readonly Argon2PasswordHasher hasher = new(FastOptions);

    [Fact]
    public void Hash_verifies()
    {
        Assert.Equal(PasswordVerifyResult.Success, hasher.Verify(Password, hasher.Hash(Password)));
    }

    [Fact]
    public void Two_hashes_of_the_same_password_differ()
    {
        string first = hasher.Hash(Password);
        string second = hasher.Hash(Password);

        Assert.NotEqual(first, second);
        Assert.NotEqual(first.Split('$')[4], second.Split('$')[4]);
    }

    [Theory]
    [InlineData("violet-canyon-7318")]
    [InlineData("Violet-canyon-7319")]
    [InlineData("violet-canyon-7319 ")]
    [InlineData("")]
    public void Wrong_password_fails(string wrong)
    {
        Assert.Equal(PasswordVerifyResult.Failed, hasher.Verify(wrong, hasher.Hash(Password)));
    }

    [Fact]
    public void Stored_value_is_a_PHC_string_with_its_parameters_and_no_plaintext()
    {
        string stored = hasher.Hash(Password);

        Assert.Matches(@"^\$argon2id\$v=19\$m=1024,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$", stored);
        Assert.DoesNotContain(Password, stored, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Production_defaults_are_the_A9_parameters_and_verify()
    {
        Argon2PasswordHasher production = new(new PasswordHashingOptions());

        string stored = production.Hash(Password);

        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", stored, StringComparison.Ordinal);
        Assert.Equal(PasswordVerifyResult.Success, production.Verify(Password, stored));
    }

    [Fact]
    public void Hash_made_with_old_parameters_verifies_but_needs_rehash()
    {
        string old = hasher.Hash(Password);
        Argon2PasswordHasher upgraded = new(new PasswordHashingOptions { MemorySizeKiB = 2048, Iterations = 2, Parallelism = 1 });

        Assert.Equal(PasswordVerifyResult.SuccessNeedsRehash, upgraded.Verify(Password, old));
        Assert.Equal(PasswordVerifyResult.Failed, upgraded.Verify("wrong-password-123", old));
        Assert.Equal(PasswordVerifyResult.Success, upgraded.Verify(Password, upgraded.Hash(Password)));
    }

    [Fact]
    public void Unicode_equivalent_input_matches_after_NFKC()
    {
        string composed = "café-terrasse-42";
        string decomposed = "café-terrasse-42";

        Assert.Equal(PasswordVerifyResult.Success, hasher.Verify(decomposed, hasher.Hash(composed)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("violet-canyon-7319")]
    [InlineData("$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=1024,t=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=262145,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=1024,t=7,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=1024,t=1,p=5$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=1024,t=1,p=1$***not-base64***$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=-5,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")]
    [InlineData("$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA$extra")]
    public void Malformed_or_out_of_bounds_stored_values_fail_without_throwing(string stored)
    {
        Assert.Equal(PasswordVerifyResult.Failed, hasher.Verify(Password, stored));
    }

    [Theory]
    [InlineData(262145, 3, 1)]
    [InlineData(65536, 7, 1)]
    [InlineData(65536, 3, 5)]
    [InlineData(65536, 0, 1)]
    [InlineData(4, 1, 1)]
    public void Options_outside_the_parse_caps_are_refused_so_every_new_hash_stays_verifiable(int memoryKiB, int iterations, int parallelism)
    {
        PasswordHashingOptions options = new() { MemorySizeKiB = memoryKiB, Iterations = iterations, Parallelism = parallelism };

        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2PasswordHasher(options));
    }

    [Fact]
    public void Caps_match_the_T06_review_limits()
    {
        Assert.Equal((262144, 6, 4), (Argon2PasswordHasher.MaxMemorySizeKiB, Argon2PasswordHasher.MaxIterations, Argon2PasswordHasher.MaxParallelism));
    }

    /// <summary>RFC 9106 section 5.3 Argon2id test vector, run against the Konscious library the hasher builds on.</summary>
    [Fact]
    public void Library_matches_the_RFC_9106_Argon2id_test_vector()
    {
        using Argon2id argon2 = new(Enumerable.Repeat((byte)0x01, 32).ToArray())
        {
            Salt = Enumerable.Repeat((byte)0x02, 16).ToArray(),
            KnownSecret = Enumerable.Repeat((byte)0x03, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)0x04, 12).ToArray(),
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };

        Assert.Equal("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", Convert.ToHexStringLower(argon2.GetBytes(32)));
    }
}
