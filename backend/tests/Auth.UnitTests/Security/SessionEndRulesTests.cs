using Auth.Api.Security;
using Auth.Contracts;
using Auth.Services.Security;

namespace Auth.UnitTests.Security;

/// <summary>T20 fix: strict cause mapping in the single-logout listener and the duplicate auth-cookie detection.</summary>
public class SessionEndRulesTests
{
    [Theory]
    [InlineData(SessionEndCause.LogoutAll)]
    [InlineData(SessionEndCause.PasswordChange)]
    [InlineData(SessionEndCause.AdminRevoked)]
    [InlineData(SessionEndCause.ApplicationDeactivated)]
    [InlineData(SessionEndCause.CodeReplay)]
    [InlineData(SessionEndCause.EmailVerified)]
    public void A_cause_that_never_cascades_has_no_revocation_reason(SessionEndCause cause) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => SingleLogoutListener.RevokedReason(cause));

    [Theory]
    [InlineData(SessionEndCause.Logout, "Logout")]
    [InlineData(SessionEndCause.SessionRevoked, "Logout")]
    [InlineData(SessionEndCause.ApplicationLogout, "Logout")]
    [InlineData(SessionEndCause.TokenReuse, "Reuse")]
    [InlineData(SessionEndCause.AccountDisabled, "Admin")]
    public void Cascading_causes_map_to_a_revocation_reason(SessionEndCause cause, string reason) =>
        Assert.Equal(reason, SingleLogoutListener.RevokedReason(cause));

    [Theory]
    [InlineData(AuthCookieNames.Refresh + "=a; " + AuthCookieNames.Refresh + "=b", AuthCookieNames.Refresh)]
    [InlineData(AuthCookieNames.Xsrf + "=a;" + AuthCookieNames.Xsrf + "=b", AuthCookieNames.Xsrf)]
    [InlineData(AuthCookieNames.AccessWithDomain + "=a; other=1; " + AuthCookieNames.AccessWithDomain + "=b", AuthCookieNames.AccessWithDomain)]
    [InlineData(AuthCookieNames.Refresh + "=a; " + AuthCookieNames.AccessWithDomain + "=b; " + AuthCookieNames.Xsrf + "=c", null)]
    [InlineData("other=1; other=2", null)]
    [InlineData("", null)]
    public void A_guarded_auth_cookie_sent_twice_is_found(string header, string? duplicate) =>
        Assert.Equal(duplicate, DuplicateCookieGuardMiddleware.FindDuplicate([header]));

    [Fact]
    public void A_duplicate_across_two_Cookie_headers_is_found() =>
        Assert.Equal(AuthCookieNames.Refresh, DuplicateCookieGuardMiddleware.FindDuplicate([AuthCookieNames.Refresh + "=a", AuthCookieNames.Refresh + "=b"]));
}
