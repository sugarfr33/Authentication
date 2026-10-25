using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Mfa;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.Api;

/// <summary>T21 optional TOTP MFA through the real host (docs/mfa-totp.md). Codes come from an independent TOTP implementation.</summary>
[Collection(ApiTestGroup.Name)]
public sealed class MfaApiTests(ApiFixture api) : IAsyncLifetime
{
    private const string Password = "violet-canyon-7319";
    private const string Mfa = "/api/v1/auth/mfa";

    private static readonly string EncryptionKey = Convert.ToBase64String([.. Enumerable.Range(1, 32).Select(i => (byte)i)]);
    private static readonly string Pepper = Convert.ToBase64String([.. Enumerable.Range(101, 32).Select(i => (byte)i)]);

    private readonly ShiftableClock clock = new();
    private readonly ConflictInjector conflicts = new();
    private WebApplicationFactory<Program> app = null!;

    public Task InitializeAsync()
    {
        app = WithSettings(MfaSettings());
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await app.DisposeAsync();

    [Fact]
    public async Task With_the_flag_off_MFA_routes_are_404_and_accounts_with_MFA_fail_closed_like_a_wrong_password()
    {
        await app.DisposeAsync();
        app = WithSettings([]);
        (_, string plainEmail, Browser plain) = await SignedInAsync();
        string mfaEmail = await SeedUserAsync(mfaEnabled: true);
        using Browser other = await NewBrowserAsync();

        HttpResponseMessage route = await plain.SendAsync(HttpMethod.Post, Mfa + "/verify", configure: r => r.Content = JsonContent.Create(new MfaVerifyRequest("123456", false)));
        HttpResponseMessage mfaUser = await PostLoginAsync(other, mfaEmail, Password);
        HttpResponseMessage wrongPassword = await PostLoginAsync(other, plainEmail, "not-the-password-1");

        Assert.Equal(HttpStatusCode.NotFound, route.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, mfaUser.StatusCode);
        Assert.Equal(await WithoutTraceAsync(wrongPassword), await WithoutTraceAsync(mfaUser));
        Assert.Contains(await AuditAsync(await UserIdAsync(mfaEmail)), a => a.EventType == nameof(AuditEventType.LoginFailed) && a.Detail!.Contains("mfa_unavailable", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Enrollment_is_confirmed_by_a_code_shows_recovery_codes_once_and_ends_every_session()
    {
        (Guid userId, _, Browser browser) = await SignedInAsync();
        string refreshBefore = browser.CookieValue(AuthCookieNames.Refresh);

        HttpResponseMessage wrongPassword = await PostJsonAsync(browser, "/enroll", new MfaEnrollRequest("not-the-password-1"));
        MfaEnrollResponse enrollment = (await (await PostJsonAsync(browser, "/enroll", new MfaEnrollRequest(Password))).Content.ReadFromJsonAsync<MfaEnrollResponse>())!;
        HttpResponseMessage wrongCode = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(WrongCode(enrollment.ManualEntryKey)));
        HttpResponseMessage confirmed = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(Code(enrollment.ManualEntryKey)));
        MfaRecoveryCodesResponse codes = (await confirmed.Content.ReadFromJsonAsync<MfaRecoveryCodesResponse>())!;

        Assert.Equal(HttpStatusCode.BadRequest, wrongPassword.StatusCode);
        Assert.StartsWith("otpauth://totp/", enrollment.OtpAuthUri, StringComparison.Ordinal);
        Assert.Contains("secret=" + enrollment.ManualEntryKey, enrollment.OtpAuthUri, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.BadRequest, wrongCode.StatusCode);
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        Assert.True(confirmed.Headers.CacheControl!.NoStore);
        Assert.Equal(10, codes.RecoveryCodes.Distinct().Count());
        Assert.All(codes.RecoveryCodes, c => Assert.Matches("^[2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}$", c));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);
        Assert.All(await QueryAsync(c => c.RefreshToken.AsNoTracking().Where(t => t.UserId == userId).ToListAsync()), t => Assert.NotNull(t.RevokedUtc));
        Assert.NotEqual(string.Empty, refreshBefore);
        User user = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId));
        Assert.True(user.MfaEnabled);
        Assert.Equal(10, await QueryAsync(c => c.MfaRecoveryCode.CountAsync(r => r.UserId == userId && r.UsedUtc == null)));
        List<AuditLog> audit = await AuditAsync(userId);
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.MfaEnabled) && a.Detail == """{"action":"enrolled"}""");
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.MfaEnrollmentStarted));
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.MfaFailed) && a.Detail == """{"reason":"wrong_code"}""");
    }

    [Fact]
    public async Task Login_with_MFA_needs_the_challenge_and_a_code_and_the_challenge_works_once()
    {
        (Guid userId, string email, string key, _) = await MfaUserAsync();
        (_, string plainEmail, _) = await SignedInAsync();
        using Browser browser = await NewBrowserAsync();

        HttpResponseMessage mfaWrongPassword = await PostLoginAsync(browser, email, "not-the-password-1");
        HttpResponseMessage plainWrongPassword = await PostLoginAsync(browser, plainEmail, "not-the-password-1");
        HttpResponseMessage login = await PostLoginAsync(browser, email, Password);
        SetCookie challenge = Assert.Single(SetCookie.From(login), c => c.Name == AuthCookieNames.MfaChallenge);
        HttpResponseMessage meBefore = await browser.GetAsync("/api/v1/auth/me");
        HttpResponseMessage wrong = await VerifyAsync(browser, WrongCode(key), false);
        HttpResponseMessage right = await VerifyAsync(browser, Code(key), false);
        HttpResponseMessage meAfter = await browser.GetAsync("/api/v1/auth/me");

        // Enumeration parity: before the password is proven, an MFA account answers exactly like any other.
        Assert.Equal((plainWrongPassword.StatusCode, await WithoutTraceAsync(plainWrongPassword)), (mfaWrongPassword.StatusCode, await WithoutTraceAsync(mfaWrongPassword)));
        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        Assert.Equal("""{"mfa_required":true}""", await login.Content.ReadAsStringAsync());
        Assert.DoesNotContain(SetCookie.From(login), c => c.Name == AuthCookieNames.Access);
        Assert.True(challenge.HasFlag("httponly") && challenge.HasFlag("secure"));
        Assert.Equal(("/api/v1/auth/mfa", "strict"), (challenge["path"], challenge["samesite"]?.ToLowerInvariant()));
        Assert.Null(challenge["domain"]);
        Assert.Equal(HttpStatusCode.Unauthorized, meBefore.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
        Assert.Equal(HttpStatusCode.OK, meAfter.StatusCode);
        Assert.Contains(SetCookie.From(right), c => c.Name == AuthCookieNames.MfaChallenge && c.IsExpired);

        // The used challenge cannot start a second session, even with the next valid code.
        using Browser replay = await NewBrowserAsync();
        replay.Plant(AuthCookieNames.MfaChallenge, challenge.Value, "/api/v1/auth/mfa");
        clock.Shift(TimeSpan.FromSeconds(30));
        Assert.Equal(HttpStatusCode.Unauthorized, (await VerifyAsync(replay, Code(key), false)).StatusCode);

        // An untrusted challenge is never attributed to the account it names (anyone can forge one naming a victim).
        Assert.DoesNotContain(await AuditAsync(userId), a => a.Detail == """{"reason":"bad_challenge"}""");

        // A code already used (same step) is refused with a fresh challenge too.
        using Browser again = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(again, email, Password)).StatusCode);
        clock.Shift(TimeSpan.FromSeconds(-30));
        Assert.Equal(HttpStatusCode.Unauthorized, (await VerifyAsync(again, Code(key), false)).StatusCode);
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.MfaVerified));
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.MfaFailed) && a.Detail == """{"reason":"replayed"}""");
    }

    [Fact]
    public async Task Wrong_codes_count_toward_the_lockout_like_wrong_passwords()
    {
        (Guid userId, string email, string key, _) = await MfaUserAsync();
        using Browser browser = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(browser, email, Password)).StatusCode);

        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await VerifyAsync(browser, WrongCode(key), i % 2 == 1)).StatusCode);
        }

        HttpResponseMessage rightButLocked = await VerifyAsync(browser, Code(key), false);
        User user = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId));

        Assert.Equal(HttpStatusCode.Unauthorized, rightButLocked.StatusCode);
        Assert.True(user.LockoutEndUtc > clock.UtcNow);
        List<AuditLog> audit = await AuditAsync(userId);
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.MfaFailed) && a.Detail == """{"reason":"wrong_recovery_code"}""");
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.Lockout));
        Assert.Contains(audit, a => a.EventType == nameof(AuditEventType.MfaFailed) && a.Detail == """{"reason":"locked"}""");
    }

    [Fact]
    public async Task A_recovery_code_works_once_even_when_used_concurrently_and_regeneration_replaces_them()
    {
        (Guid userId, string email, string key, IReadOnlyList<string> codes) = await MfaUserAsync();
        using Browser first = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(first, email, Password)).StatusCode);
        HttpResponseMessage used = await VerifyAsync(first, codes[0].Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant(), true);
        Assert.Equal(HttpStatusCode.OK, used.StatusCode);

        using Browser reuse = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(reuse, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await VerifyAsync(reuse, codes[0], true)).StatusCode);

        // Two browsers race with the same unused code: exactly one session starts.
        using Browser a = await NewBrowserAsync();
        using Browser b = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(a, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(b, email, Password)).StatusCode);
        HttpResponseMessage[] race = await Task.WhenAll(VerifyAsync(a, codes[1], true), VerifyAsync(b, codes[1], true));
        Assert.Single(race, r => r.StatusCode == HttpStatusCode.OK);

        // Regenerate (password plus a TOTP code): old unused codes die, new ones work.
        clock.Shift(TimeSpan.FromSeconds(30));
        MfaRecoveryCodesResponse fresh = (await (await PostJsonAsync(first, "/recovery-codes", new MfaFactorsRequest(Password, Code(key), false))).Content.ReadFromJsonAsync<MfaRecoveryCodesResponse>())!;
        using Browser old = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(old, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await VerifyAsync(old, codes[2], true)).StatusCode);
        using Browser renewed = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(renewed, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(renewed, fresh.RecoveryCodes[0], true)).StatusCode);

        Assert.Equal(10, fresh.RecoveryCodes.Count);
        Assert.Equal(3, (await AuditAsync(userId)).Count(r => r.EventType == nameof(AuditEventType.MfaRecoveryCodeUsed)));
    }

    [Fact]
    public async Task Disabling_needs_the_password_and_a_code_and_ends_every_session()
    {
        (Guid userId, string email, string key, _) = await MfaUserAsync();
        using Browser browser = await MfaSignedInAsync(email, key);
        clock.Shift(TimeSpan.FromSeconds(30));
        using Browser other = await MfaSignedInAsync(email, key);
        clock.Shift(TimeSpan.FromSeconds(30));

        HttpResponseMessage wrong = await PostJsonAsync(browser, "/disable", new MfaFactorsRequest(Password, WrongCode(key), false));
        HttpResponseMessage disabled = await PostJsonAsync(browser, "/disable", new MfaFactorsRequest(Password, Code(key), false));

        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, disabled.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/api/v1/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);
        using Browser plain = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(plain, email, Password)).StatusCode);
        User user = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId));
        Assert.False(user.MfaEnabled);
        Assert.Null(user.MfaSecretEncrypted);
        Assert.Equal(0, await QueryAsync(c => c.MfaRecoveryCode.CountAsync(r => r.UserId == userId && r.UsedUtc == null)));
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.MfaDisabled) && a.Detail == """{"action":"disabled"}""");
    }

    [Fact]
    public async Task An_admin_reset_turns_MFA_off_and_ends_every_session()
    {
        (Guid userId, string email, string key, _) = await MfaUserAsync();
        using Browser browser = await MfaSignedInAsync(email, key);

        await using (AsyncServiceScope scope = app.Services.CreateAsyncScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<IMfaService>().ResetAsync(userId, AuditContext.None, CancellationToken.None));
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/v1/auth/me")).StatusCode);
        using Browser plain = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(plain, email, Password)).StatusCode);
        Assert.Contains(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.MfaDisabled) && a.Detail == """{"action":"reset"}""");
    }

    [Fact]
    public async Task A_verify_that_loses_a_race_is_retried_and_a_lost_recovery_code_spend_is_rolled_back()
    {
        (Guid userId, string email, string key, IReadOnlyList<string> codes) = await MfaUserAsync();

        // One lost RowVersion race (e.g. a concurrent lockout write): checked again against fresh state, it succeeds.
        using Browser browser = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(browser, email, Password)).StatusCode);
        conflicts.Arm(userId, 1);
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(browser, Code(key), false)).StatusCode);
        Assert.DoesNotContain(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.MfaFailed));

        // Losing twice: refused without a strike, and the recovery code spend is rolled back, so the code still works.
        using Browser second = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(second, email, Password)).StatusCode);
        conflicts.Arm(userId, 2);
        HttpResponseMessage lost = await VerifyAsync(second, codes[0], true);
        User afterLoss = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId));
        int unusedAfterLoss = await QueryAsync(c => c.MfaRecoveryCode.CountAsync(r => r.UserId == userId && r.UsedUtc == null));
        HttpResponseMessage retried = await VerifyAsync(second, codes[0], true);

        Assert.Equal(HttpStatusCode.Unauthorized, lost.StatusCode);
        Assert.Equal(0, afterLoss.FailedLoginCount);
        Assert.Equal(10, unusedAfterLoss);
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        List<AuditLog> audit = await AuditAsync(userId);
        Assert.Equal(["""{"reason":"conflict"}"""], audit.Where(a => a.EventType == nameof(AuditEventType.MfaFailed)).Select(a => a.Detail));
    }

    [Fact]
    public async Task A_double_submitted_code_starts_one_session_and_the_loser_is_not_a_strike()
    {
        (Guid userId, string email, string key, IReadOnlyList<string> codes) = await MfaUserAsync();
        using Browser a = await NewBrowserAsync();
        using Browser b = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(a, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(b, email, Password)).StatusCode);
        string code = Code(key);
        HttpResponseMessage[] totp = await Task.WhenAll(VerifyAsync(a, code, false), VerifyAsync(b, code, false));

        using Browser c = await NewBrowserAsync();
        using Browser d = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(c, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(d, email, Password)).StatusCode);
        HttpResponseMessage[] recovery = await Task.WhenAll(VerifyAsync(c, codes[0], true), VerifyAsync(d, codes[0], true));

        Assert.Single(totp, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(totp, r => r.StatusCode == HttpStatusCode.Unauthorized);
        Assert.Single(recovery, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(recovery, r => r.StatusCode == HttpStatusCode.Unauthorized);
        Assert.DoesNotContain(await AuditAsync(userId), r => r.EventType == nameof(AuditEventType.MfaFailed));
        Assert.Equal(0, (await QueryAsync(q => q.User.AsNoTracking().SingleAsync(u => u.Id == userId))).FailedLoginCount);
    }

    [Fact]
    public async Task A_confirm_that_loses_a_race_answers_409_never_500_and_is_not_a_strike()
    {
        (Guid userId, _, Browser browser) = await SignedInAsync();
        using (browser)
        {
            MfaEnrollResponse enrollment = (await (await PostJsonAsync(browser, "/enroll", new MfaEnrollRequest(Password))).Content.ReadFromJsonAsync<MfaEnrollResponse>())!;
            conflicts.Arm(userId, 1);
            HttpResponseMessage lost = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(Code(enrollment.ManualEntryKey)));
            User afterLoss = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId));
            int codesAfterLoss = await QueryAsync(c => c.MfaRecoveryCode.CountAsync(r => r.UserId == userId));
            HttpResponseMessage again = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(Code(enrollment.ManualEntryKey)));

            Assert.Equal(HttpStatusCode.Conflict, lost.StatusCode);
            Assert.False(afterLoss.MfaEnabled);
            Assert.Equal(0, afterLoss.FailedLoginCount);
            Assert.Equal(0, codesAfterLoss);
            Assert.Equal(HttpStatusCode.OK, again.StatusCode);
            Assert.DoesNotContain(await AuditAsync(userId), a => a.EventType == nameof(AuditEventType.MfaFailed));
        }

        // Two real concurrent confirms with the same code: one turns MFA on, the other is refused, never a 500.
        (Guid otherId, _, Browser other) = await SignedInAsync();
        using (other)
        {
            MfaEnrollResponse enrollment = (await (await PostJsonAsync(other, "/enroll", new MfaEnrollRequest(Password))).Content.ReadFromJsonAsync<MfaEnrollResponse>())!;
            string code = Code(enrollment.ManualEntryKey);
            HttpResponseMessage[] race = await Task.WhenAll(
                PostJsonAsync(other, "/confirm", new MfaConfirmRequest(code)),
                PostJsonAsync(other, "/confirm", new MfaConfirmRequest(code)));

            Assert.Single(race, r => r.StatusCode == HttpStatusCode.OK);
            Assert.All(race, r => Assert.True((int)r.StatusCode < 500, "confirm answered " + r.StatusCode));
            Assert.Equal(10, await QueryAsync(c => c.MfaRecoveryCode.CountAsync(r => r.UserId == otherId && r.UsedUtc == null)));
        }
    }

    [Fact]
    public async Task A_pending_enrollment_expires_after_15_minutes()
    {
        (_, _, Browser browser) = await SignedInAsync();
        using (browser)
        {
            MfaEnrollResponse stale = (await (await PostJsonAsync(browser, "/enroll", new MfaEnrollRequest(Password))).Content.ReadFromJsonAsync<MfaEnrollResponse>())!;
            clock.Shift(TimeSpan.FromMinutes(16));
            HttpResponseMessage expired = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(Code(stale.ManualEntryKey)));
            MfaEnrollResponse fresh = (await (await PostJsonAsync(browser, "/enroll", new MfaEnrollRequest(Password))).Content.ReadFromJsonAsync<MfaEnrollResponse>())!;
            HttpResponseMessage confirmed = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(Code(fresh.ManualEntryKey)));

            Assert.Equal(HttpStatusCode.Conflict, expired.StatusCode);
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        }
    }

    [Fact]
    public async Task Secrets_codes_and_challenges_never_reach_logs_or_audit_rows()
    {
        (Guid userId, string email, string key, IReadOnlyList<string> codes) = await MfaUserAsync();
        using Browser browser = await NewBrowserAsync();
        HttpResponseMessage login = await PostLoginAsync(browser, email, Password);
        string challenge = SetCookie.From(login).Single(c => c.Name == AuthCookieNames.MfaChallenge).Value;
        string wrong = WrongCode(key);
        await VerifyAsync(browser, wrong, false);
        string right = Code(key);
        await VerifyAsync(browser, right, false);

        string[] secrets = [key, challenge, right, wrong, .. codes, .. codes.Select(c => c.Replace("-", string.Empty, StringComparison.Ordinal))];
        string audit = string.Join("|", (await AuditAsync(userId)).Select(r => r.Detail + r.UserAgent + r.IpAddress));
        Assert.All(secrets, s => Assert.DoesNotContain(s, audit, StringComparison.Ordinal));
        Assert.All(secrets, s => Assert.DoesNotContain(api.Logs.Texts, l => l.Contains(s, StringComparison.Ordinal)));
        User user = await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Id == userId));
        Assert.True(user.MfaSecretEncrypted!.AsSpan().IndexOf(Base32Decode(key)) < 0, "the secret is stored encrypted");
    }

    [Fact]
    public void With_the_flag_on_missing_keys_stop_the_host()
    {
        Dictionary<string, string?> settings = MfaSettings();
        settings.Remove("Secrets:MfaRecoveryPepper");
        using WebApplicationFactory<Program> broken = WithSettings(settings);

        Assert.ThrowsAny<Exception>(() => broken.CreateClient());
    }

    private static Dictionary<string, string?> MfaSettings() => new()
    {
        ["Mfa:Enabled"] = "true",
        ["Mfa:ActiveKeyId"] = "k1",
        ["Mfa:KeyIds:0"] = "k1",
        ["Secrets:MfaEncryptionKey-k1"] = EncryptionKey,
        ["Secrets:MfaRecoveryPepper"] = Pepper,
    };

    private WebApplicationFactory<Program> WithSettings(Dictionary<string, string?> extra)
    {
        Dictionary<string, string?> settings = new(extra)
        {
            ["RateLimiting:Policies:Login:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:Login:PerAccount:PermitLimit"] = "1000",
            ["RateLimiting:Policies:MfaVerify:PerIp:PermitLimit"] = "1000",
            ["RateLimiting:Policies:MfaManage:PerIp:PermitLimit"] = "1000",
        };
        return api.Factory.WithWebHostBuilder(builder =>
        {
            foreach (KeyValuePair<string, string?> setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(settings));
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<IClock>(clock);
                services.AddScoped<IUnitOfWork>(sp => new ConflictingUnitOfWork(
                    new UnitOfWork(sp.GetRequiredService<AuthDbContext>()), sp.GetRequiredService<AuthDbContext>(), sp.GetRequiredService<IServiceScopeFactory>(), conflicts));
            });
        });
    }

    /// <summary>A user with confirmed MFA (signed out by the confirmation), its key and its recovery codes.</summary>
    private async Task<(Guid UserId, string Email, string Key, IReadOnlyList<string> Codes)> MfaUserAsync()
    {
        (Guid userId, string email, Browser browser) = await SignedInAsync();
        using (browser)
        {
            MfaEnrollResponse enrollment = (await (await PostJsonAsync(browser, "/enroll", new MfaEnrollRequest(Password))).Content.ReadFromJsonAsync<MfaEnrollResponse>())!;
            HttpResponseMessage confirmed = await PostJsonAsync(browser, "/confirm", new MfaConfirmRequest(Code(enrollment.ManualEntryKey)));
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
            clock.Shift(TimeSpan.FromSeconds(30));
            return (userId, email, enrollment.ManualEntryKey, (await confirmed.Content.ReadFromJsonAsync<MfaRecoveryCodesResponse>())!.RecoveryCodes);
        }
    }

    private async Task<Browser> MfaSignedInAsync(string email, string key)
    {
        Browser browser = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.Accepted, (await PostLoginAsync(browser, email, Password)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(browser, Code(key), false)).StatusCode);
        return browser;
    }

    private string Code(string key) => Totp(Base32Decode(key), (long)Math.Floor((clock.UtcNow - DateTime.UnixEpoch).TotalSeconds / 30));

    private string WrongCode(string key) => ((int.Parse(Code(key), System.Globalization.CultureInfo.InvariantCulture) + 500000) % 1000000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>An independent RFC 6238 implementation for the tests (HMAC-SHA1, 6 digits).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "RFC 6238 TOTP uses HMAC-SHA1.")]
    private static string Totp(byte[] secret, long step)
    {
        byte[] counter = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        byte[] mac = HMACSHA1.HashData(secret, counter);
        int offset = mac[19] & 0xF;
        int value = (BinaryPrimitives.ReadInt32BigEndian(mac.AsSpan(offset, 4)) & 0x7FFFFFFF) % 1000000;
        return value.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static byte[] Base32Decode(string text)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        List<byte> output = [];
        int buffer = 0;
        int bits = 0;
        foreach (char c in text)
        {
            buffer = (buffer << 5) | Alphabet.IndexOf(c, StringComparison.Ordinal);
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }

        return [.. output];
    }

    /// <summary>The ProblemDetails body without its per-request traceId.</summary>
    private static async Task<string> WithoutTraceAsync(HttpResponseMessage response)
    {
        System.Text.Json.Nodes.JsonObject body = System.Text.Json.Nodes.JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        body.Remove("traceId");
        return body.ToJsonString();
    }

    private static Task<HttpResponseMessage> PostJsonAsync<T>(Browser browser, string path, T body) =>
        browser.SendAsync(HttpMethod.Post, Mfa + path, configure: r => r.Content = JsonContent.Create(body));

    private static Task<HttpResponseMessage> VerifyAsync(Browser browser, string code, bool recovery) =>
        PostJsonAsync(browser, "/verify", new MfaVerifyRequest(code, recovery));

    private static Task<HttpResponseMessage> PostLoginAsync(Browser browser, string email, string password) =>
        browser.SendAsync(HttpMethod.Post, "/api/v1/auth/login", configure: r =>
            r.Content = new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { [AuthRequestFields.Email] = email, ["password"] = password }), Encoding.UTF8, "application/json"));

    private async Task<Browser> NewBrowserAsync()
    {
        Browser browser = new(app);
        await browser.GetAsync(TestEndpoints.Prefix + "/ping");
        return browser;
    }

    private async Task<(Guid UserId, string Email, Browser Browser)> SignedInAsync()
    {
        string email = await SeedUserAsync(mfaEnabled: false);
        Browser browser = await NewBrowserAsync();
        Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(browser, email, Password)).StatusCode);
        return (await UserIdAsync(email), email, browser);
    }

    private async Task<string> SeedUserAsync(bool mfaEnabled)
    {
        string email = "mfa-" + Guid.NewGuid().ToString("N")[..12] + "@example.test";
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        string hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(Password, CancellationToken.None);
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        DateTime now = DateTime.UtcNow;
        context.User.Add(new User
        {
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email)!,
            EmailVerified = true,
            PasswordHash = hash,
            DisplayName = "MFA Tester",
            IsActive = true,
            MfaEnabled = mfaEnabled,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = now,
            UpdatedUtc = now,
        });
        await context.SaveChangesAsync();
        return email;
    }

    private async Task<Guid> UserIdAsync(string email) => (await QueryAsync(c => c.User.AsNoTracking().SingleAsync(u => u.Email == email))).Id;

    private Task<List<AuditLog>> AuditAsync(Guid userId) => QueryAsync(c => c.AuditLog.AsNoTracking().Where(a => a.UserId == userId).ToListAsync());

    private async Task<T> QueryAsync<T>(Func<AuthDbContext, Task<T>> query)
    {
        await using AsyncServiceScope scope = app.Services.CreateAsyncScope();
        return await query(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
    }

    /// <summary>Makes the next N saves that update the given user lose the RowVersion race (a concurrent write first).</summary>
    private sealed class ConflictInjector
    {
        private int remaining;

        public Guid UserId { get; private set; }

        public void Arm(Guid userId, int saves)
        {
            UserId = userId;
            Volatile.Write(ref remaining, saves);
        }

        public bool TryTake(AuthDbContext context) =>
            Volatile.Read(ref remaining) > 0
            && context.ChangeTracker.Entries<User>().Any(e => e.State == EntityState.Modified && e.Entity.Id == UserId)
            && Interlocked.Decrement(ref remaining) >= 0;
    }

    private sealed class ConflictingUnitOfWork(IUnitOfWork inner, AuthDbContext context, IServiceScopeFactory scopes, ConflictInjector injector) : IUnitOfWork
    {
        public Task<IUnitOfWorkTransaction> BeginTransactionAsync(System.Data.IsolationLevel isolationLevel, CancellationToken cancellationToken) =>
            inner.BeginTransactionAsync(isolationLevel, cancellationToken);

        public void ClearChanges() => inner.ClearChanges();

        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken)
        {
            if (injector.TryTake(context))
            {
                await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<AuthDbContext>().User
                    .Where(u => u.Id == injector.UserId)
                    .ExecuteUpdateAsync(u => u.SetProperty(x => x.LastLoginUtc, DateTime.UtcNow), cancellationToken);
            }

            return await inner.SaveChangesAsync(cancellationToken);
        }
    }

    private sealed class ShiftableClock : IClock
    {
        private long offsetTicks;

        public DateTime UtcNow => DateTime.UtcNow.AddTicks(Interlocked.Read(ref offsetTicks));

        public void Shift(TimeSpan by) => Interlocked.Add(ref offsetTicks, by.Ticks);
    }
}
