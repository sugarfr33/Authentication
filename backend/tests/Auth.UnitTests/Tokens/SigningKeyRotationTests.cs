using Auth.Contracts;
using Auth.Contracts.Responses;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Tokens;

namespace Auth.UnitTests.Tokens;

/// <summary>Plan A6 rotation with a fake clock: publish before activation, overlap after, then drop.</summary>
public sealed class SigningKeyRotationTests : IDisposable
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private readonly KeyHarness harness = new(new TokenOptions { Issuer = "https://auth.example.test", KeyCacheDuration = TimeSpan.Zero });

    private TimeSpan Overlap => harness.Options.KeyOverlap;

    [Fact]
    public void Overlap_is_token_lifetime_plus_skew()
    {
        Assert.Equal(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(30), Overlap);
    }

    [Fact]
    public async Task First_key_may_activate_immediately_and_signs()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);

        Assert.Equal("k1", (await harness.Provider.GetSigningKeyAsync(Ct)).Kid);
        Assert.Equal(["k1"], await JwksKidsAsync());
    }

    [Fact]
    public async Task First_key_with_a_slightly_past_activation_starts_now()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start - TimeSpan.FromMilliseconds(5));

        Assert.Equal(KeyHarness.Start, harness.Repository.Get("k1").ActivatedUtc);
        Assert.Equal("k1", (await harness.Provider.GetSigningKeyAsync(Ct)).Kid);
    }

    [Fact]
    public async Task No_key_means_no_signing()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Provider.GetSigningKeyAsync(Ct));
        Assert.Empty(await JwksKidsAsync());
    }

    [Fact]
    public async Task Next_key_must_be_published_at_least_lifetime_plus_skew_before_it_signs()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => harness.AddKeyAsync("k2", KeyHarness.Start + Overlap - TimeSpan.FromSeconds(1)));
        await harness.AddKeyAsync("k2", KeyHarness.Start + Overlap);
    }

    /// <summary>
    /// T20 (T07/T09 review): a key that is only published (future-dated, nothing signs yet) may already be cached by
    /// resource servers, so a further key needs the full overlap too; it is no longer a bootstrap.
    /// </summary>
    [Fact]
    public async Task A_published_future_key_requires_the_overlap_for_the_next_key()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        await harness.AddKeyAsync("k2", KeyHarness.Start + Overlap + Overlap);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => harness.AddKeyAsync("k3", KeyHarness.Start + Overlap - TimeSpan.FromSeconds(1)));
        await harness.AddKeyAsync("k3", KeyHarness.Start + Overlap);
    }

    [Fact]
    public async Task With_only_a_future_dated_key_published_a_new_key_cannot_start_now()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start + Overlap);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => harness.AddKeyAsync("k2", KeyHarness.Start));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => harness.AddKeyAsync("k2", KeyHarness.Start - TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public async Task New_key_is_in_the_JWKS_before_it_activates_while_the_old_key_keeps_signing()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        DateTime k2Activation = KeyHarness.Start + Overlap;
        await harness.AddKeyAsync("k2", k2Activation);

        Assert.Equal(["k1", "k2"], await JwksKidsAsync());
        Assert.Equal("k1", (await harness.Provider.GetSigningKeyAsync(Ct)).Kid);

        harness.Clock.Set(k2Activation - TimeSpan.FromTicks(1));
        Assert.Equal("k1", (await harness.Provider.GetSigningKeyAsync(Ct)).Kid);

        harness.Clock.Set(k2Activation);
        Assert.Equal("k2", (await harness.Provider.GetSigningKeyAsync(Ct)).Kid);
    }

    [Fact]
    public async Task Superseded_key_stays_published_until_RetireAfterUtc_then_is_dropped_and_retired()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        DateTime k2Activation = KeyHarness.Start + Overlap;
        await harness.AddKeyAsync("k2", k2Activation);
        harness.Clock.Set(k2Activation + TimeSpan.FromMinutes(1));

        Assert.Equal(1, await harness.Rotation.RetireSupersededAsync(Ct));

        SigningKey k1 = harness.Repository.Get("k1");
        Assert.Equal(SigningKeyStatus.Retiring, k1.Status);
        Assert.Equal(k2Activation + Overlap, k1.RetireAfterUtc);
        Assert.True(k1.RetireAfterUtc - k2Activation >= harness.Options.AccessTokenLifetime + harness.Options.ClockSkew);

        harness.Clock.Set(k2Activation + Overlap - TimeSpan.FromTicks(1));
        Assert.Equal(["k1", "k2"], await JwksKidsAsync());
        Assert.Contains("k1", (await harness.Provider.GetValidationKeysAsync(Ct)).Select(k => k.Kid));

        harness.Clock.Set(k2Activation + Overlap);
        Assert.Equal(["k2"], await JwksKidsAsync());
        Assert.DoesNotContain("k1", (await harness.Provider.GetValidationKeysAsync(Ct)).Select(k => k.Kid));

        Assert.Equal(1, await harness.Rotation.RetireSupersededAsync(Ct));
        Assert.Equal(SigningKeyStatus.Retired, harness.Repository.Get("k1").Status);
        Assert.Equal(0, await harness.Rotation.RetireSupersededAsync(Ct));
    }

    [Fact]
    public async Task A_future_key_is_not_retired_as_superseded()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        await harness.AddKeyAsync("k2", KeyHarness.Start + Overlap);

        Assert.Equal(0, await harness.Rotation.RetireSupersededAsync(Ct));
        Assert.Equal(SigningKeyStatus.Active, harness.Repository.Get("k2").Status);
    }

    [Fact]
    public async Task Rows_are_cached_for_KeyCacheDuration_and_rotation_invalidates_the_cache()
    {
        using KeyHarness cached = new(new TokenOptions { Issuer = "https://auth.example.test", KeyCacheDuration = TimeSpan.FromMinutes(1) });
        await cached.AddKeyAsync("k1", KeyHarness.Start);
        await cached.Provider.GetJwksAsync(Ct);
        int reads = cached.Repository.Reads;

        await cached.Provider.GetJwksAsync(Ct);
        await cached.Provider.GetSigningKeyAsync(Ct);
        Assert.Equal(reads, cached.Repository.Reads);

        cached.Clock.Advance(TimeSpan.FromMinutes(1));
        await cached.Provider.GetJwksAsync(Ct);
        Assert.Equal(reads + 1, cached.Repository.Reads);

        await cached.AddKeyAsync("k2", cached.Clock.UtcNow + cached.Options.KeyOverlap);
        Assert.Equal(2, (await cached.Provider.GetJwksAsync(Ct)).Keys.Count);
    }

    [Fact]
    public async Task Duplicate_kid_and_unsupported_algorithm_are_refused()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.AddKeyAsync("k1", KeyHarness.Start + Overlap));
        await Assert.ThrowsAsync<ArgumentException>(
            () => harness.Rotation.AddKeyAsync("k9", "HS256", "ref-k9", KeyHarness.Start + Overlap, Ct));
    }

    [Fact]
    public async Task An_added_key_stages_one_SigningKeyAdded_row_with_kid_algorithm_and_activation_only()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);
        await harness.AddKeyAsync("k2", KeyHarness.Start + Overlap, SigningKeyAlgorithm.RS256);

        Assert.Equal([AuditEventType.SigningKeyAdded, AuditEventType.SigningKeyAdded], harness.Audit.Staged.Select(e => e.Type));
        Assert.All(harness.Audit.Staged, e => Assert.Null(e.UserId));
        Assert.Equal("""{"kid":"k1","algorithm":"ES256","activates":"2026-10-24T12:00:00.0000000Z"}""", AuditDetail.Render(harness.Audit.Staged[0]));
        Assert.Equal("""{"kid":"k2","algorithm":"RS256","activates":"2026-10-24T12:15:30.0000000Z"}""", AuditDetail.Render(harness.Audit.Staged[1]));
        Assert.DoesNotContain("ref-", AuditDetail.Render(harness.Audit.Staged[0])!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_key_stages_no_audit_row()
    {
        await harness.AddKeyAsync("k1", KeyHarness.Start);

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.AddKeyAsync("k1", KeyHarness.Start + Overlap));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => harness.AddKeyAsync("k2", KeyHarness.Start));

        Assert.Single(harness.Audit.Staged);
    }

    private async Task<IReadOnlyList<string>> JwksKidsAsync()
    {
        JwksDocument jwks = await harness.Provider.GetJwksAsync(Ct);
        return jwks.Keys.Select(k => k.Kid).ToList();
    }

    public void Dispose() => harness.Dispose();
}
