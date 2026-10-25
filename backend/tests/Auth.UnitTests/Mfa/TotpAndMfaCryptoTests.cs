using System.Text;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Mfa;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.UnitTests.Mfa;

/// <summary>T21: RFC 6238 vectors, window and replay rules, base32, the encrypted secret blob and the login challenge.</summary>
public class TotpAndMfaCryptoTests
{
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    /// <summary>RFC 6238 appendix B, SHA-1, 8 digits.</summary>
    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void The_RFC_6238_SHA1_vectors_match(long unixSeconds, string expected) =>
        Assert.Equal(expected, Totp.Compute(RfcSecret, unixSeconds / Totp.StepSeconds, 8));

    [Fact]
    public void Six_digit_codes_are_the_last_six_digits_and_the_step_comes_from_the_clock()
    {
        Assert.Equal("287082", Totp.Compute(RfcSecret, 59 / 30));
        Assert.Equal(1L, Totp.StepAt(DateTime.UnixEpoch.AddSeconds(59)));
    }

    [Fact]
    public void A_code_matches_within_one_step_either_way_and_never_a_step_already_used()
    {
        const long now = 1000;
        string previous = Totp.Compute(RfcSecret, now - 1);
        string next = Totp.Compute(RfcSecret, now + 1);
        string twoAhead = Totp.Compute(RfcSecret, now + 2);

        Assert.Equal(now - 1, Totp.Match(RfcSecret, previous, now, lastUsedStep: 0));
        Assert.Equal(now + 1, Totp.Match(RfcSecret, next, now, lastUsedStep: 0));
        Assert.Null(Totp.Match(RfcSecret, twoAhead, now, lastUsedStep: 0));
        Assert.Null(Totp.Match(RfcSecret, previous, now, lastUsedStep: now - 1));
        Assert.True(Totp.IsReplay(RfcSecret, previous, now, lastUsedStep: now - 1));
        Assert.Equal(now, Totp.Match(RfcSecret, Totp.Compute(RfcSecret, now), now, lastUsedStep: now - 1));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12a456")]
    [InlineData("１２３４５６")]
    public void Malformed_codes_never_match(string? code) => Assert.Null(Totp.Normalize(code));

    [Fact]
    public void Spaces_are_ignored_in_codes() => Assert.Equal("123456", Totp.Normalize("123 456"));

    /// <summary>RFC 4648 section 10, without padding.</summary>
    [Theory]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_matches_RFC_4648(string input, string expected) => Assert.Equal(expected, Base32.Encode(Encoding.ASCII.GetBytes(input)));

    [Theory]
    [InlineData("abcde-fghjk", "ABCDEFGHJK")]
    [InlineData("ABCDE FGHJK", "ABCDEFGHJK")]
    [InlineData("ABCDEFGHJ", null)]
    [InlineData("ABCDEFGHIK", null)]
    [InlineData("ABCDE0GHJK", null)]
    public void Recovery_codes_are_normalized_to_the_unambiguous_alphabet(string input, string? expected) =>
        Assert.Equal(expected, MfaService.NormalizeRecoveryCode(input));

    [Fact]
    public async Task The_secret_blob_round_trips_and_is_bound_to_the_user_and_the_key()
    {
        Guid user = Guid.NewGuid();
        MfaCrypto crypto = Crypto(("k1", 1));
        byte[] secret = [.. Enumerable.Range(0, 20).Select(i => (byte)i)];
        byte[] blob = await crypto.ProtectAsync(user, new MfaSecret(secret, 42), CancellationToken.None);

        MfaSecret? back = await crypto.UnprotectAsync(user, blob, CancellationToken.None);
        byte[] tampered = [.. blob];
        tampered[^1] ^= 1;

        Assert.Equal(secret, back!.Secret);
        Assert.Equal(42L, back.LastUsedStep);
        Assert.True(blob.AsSpan().IndexOf(secret) < 0);
        Assert.Null(await crypto.UnprotectAsync(Guid.NewGuid(), blob, CancellationToken.None));
        Assert.Null(await crypto.UnprotectAsync(user, tampered, CancellationToken.None));
        Assert.Null(await crypto.UnprotectAsync(user, [9, 9, 9], CancellationToken.None));
        Assert.NotEqual(blob, await crypto.ProtectAsync(user, new MfaSecret(secret, 42), CancellationToken.None));
    }

    [Fact]
    public async Task A_rotated_key_still_decrypts_old_blobs_and_new_blobs_use_the_active_key()
    {
        Guid user = Guid.NewGuid();
        byte[] secret = new byte[20];
        byte[] old = await Crypto(("k1", 1)).ProtectAsync(user, new MfaSecret(secret, 7), CancellationToken.None);
        MfaCrypto rotated = Crypto(("k2", 2), ("k1", 1));

        Assert.Equal(7L, (await rotated.UnprotectAsync(user, old, CancellationToken.None))!.LastUsedStep);
        Assert.Equal("k2", Encoding.ASCII.GetString(await rotated.ProtectAsync(user, new MfaSecret(secret, 8), CancellationToken.None), 2, 2));
        Assert.Null(await Crypto(("k2", 2)).UnprotectAsync(user, old, CancellationToken.None));
    }

    [Fact]
    public async Task Missing_or_short_keys_are_refused()
    {
        MfaOptions options = new() { Enabled = true, ActiveKeyId = "k1" };
        options.KeyIds.Add("k1");
        MfaCrypto missing = new(new Secrets(new Dictionary<string, string>()), options, NullLogger<MfaCrypto>.Instance);
        MfaCrypto shortKey = new(new Secrets(new Dictionary<string, string> { ["MfaEncryptionKey-k1"] = Convert.ToBase64String(new byte[16]), ["MfaRecoveryPepper"] = Key(3) }), options, NullLogger<MfaCrypto>.Instance);
        MfaCrypto pepperIsAKey = new(new Secrets(new Dictionary<string, string> { ["MfaEncryptionKey-k1"] = Key(3), ["MfaRecoveryPepper"] = Key(3) }), options, NullLogger<MfaCrypto>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() => missing.ValidateKeysAsync(CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => shortKey.ValidateKeysAsync(CancellationToken.None));
        InvalidOperationException same = await Assert.ThrowsAsync<InvalidOperationException>(() => pepperIsAKey.ValidateKeysAsync(CancellationToken.None));
        Assert.Contains("must differ", same.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreadable_blob_logs_one_warning_per_minute_with_the_key_id_only()
    {
        Guid user = Guid.NewGuid();
        byte[] blob = await Crypto(("old", 1)).ProtectAsync(user, new MfaSecret(new byte[20], 3), CancellationToken.None);
        CapturingLogger logger = new();
        MfaCrypto dropped = Crypto(logger, ("k2", 2));
        byte[] tampered = await Crypto(("k2", 2)).ProtectAsync(user, new MfaSecret(new byte[20], 3), CancellationToken.None);
        tampered[^1] ^= 1;

        Assert.Null(await dropped.UnprotectAsync(user, blob, CancellationToken.None));
        Assert.Null(await dropped.UnprotectAsync(user, blob, CancellationToken.None));
        Assert.Null(await dropped.UnprotectAsync(user, tampered, CancellationToken.None));

        Assert.Equal(2, logger.Messages.Count);
        Assert.Contains("unknown_key, key id old", logger.Messages[0], StringComparison.Ordinal);
        Assert.Contains("tag_mismatch, key id k2", logger.Messages[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_challenge_verifies_once_for_the_same_user_agent_and_account_state_and_expires()
    {
        Clock clock = new() { UtcNow = new DateTime(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc) };
        MfaCrypto crypto = Crypto(("k1", 1));
        MfaChallenges challenges = new(crypto, new MfaOptions { Enabled = true }, clock);
        User user = new() { Id = Guid.NewGuid(), SecurityStamp = Guid.NewGuid(), MfaSecretEncrypted = [1, 2, 3] };

        string challenge = await challenges.CreateAsync(user, "agent", CancellationToken.None);
        string altered = challenge[..^2] + (challenge[^2] == 'A' ? "B" : "A") + challenge[^1];

        Assert.Equal(user.Id, challenges.ReadUserId(challenge));
        Assert.True(await challenges.VerifyAsync(challenge, user, "agent", CancellationToken.None));
        Assert.False(await challenges.VerifyAsync(challenge, user, "other agent", CancellationToken.None));
        Assert.False(await challenges.VerifyAsync(altered, user, "agent", CancellationToken.None));

        user.MfaSecretEncrypted = [1, 2, 4];
        Assert.False(await challenges.VerifyAsync(challenge, user, "agent", CancellationToken.None));

        clock.UtcNow += TimeSpan.FromMinutes(6);
        Assert.Null(challenges.ReadUserId(challenge));
    }

    [Fact]
    public void Options_refuse_an_active_key_that_is_not_listed()
    {
        MfaOptions options = new() { Enabled = true, ActiveKeyId = "k2" };
        options.KeyIds.Add("k1");

        Assert.Throws<InvalidOperationException>(() => options.Validated());
        Assert.False(new MfaOptions().Validated().Enabled);
    }

    private static string Key(int seed) => Convert.ToBase64String([.. Enumerable.Range(seed, 32).Select(i => (byte)i)]);

    private static MfaCrypto Crypto(params (string Id, int Seed)[] keys) => Crypto(NullLogger<MfaCrypto>.Instance, keys);

    private static MfaCrypto Crypto(ILogger<MfaCrypto> logger, params (string Id, int Seed)[] keys)
    {
        MfaOptions options = new() { Enabled = true, ActiveKeyId = keys[0].Id };
        Dictionary<string, string> secrets = new() { ["MfaRecoveryPepper"] = Key(200) };
        foreach ((string id, int seed) in keys)
        {
            options.KeyIds.Add(id);
            secrets["MfaEncryptionKey-" + id] = Key(seed);
        }

        return new MfaCrypto(new Secrets(secrets), options, logger);
    }

    private sealed class CapturingLogger : ILogger<MfaCrypto>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }

    private sealed class Secrets(Dictionary<string, string> values) : ISecretStore
    {
        public Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(values.TryGetValue(name, out string? value) ? value : null);
    }

    private sealed class Clock : IClock
    {
        public DateTime UtcNow { get; set; }
    }
}
