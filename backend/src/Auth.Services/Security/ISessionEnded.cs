using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;

namespace Auth.Services.Security;

/// <summary>Why sessions ended. The audit words are the lower-case snake_case names (AuditEvents.CauseWord).</summary>
public enum SessionEndCause
{
    /// <summary>The browser signed out (POST /auth/logout), or another user signed in on the same browser.</summary>
    Logout = 1,

    /// <summary>Every session of the user (POST /auth/logout-all).</summary>
    LogoutAll,

    /// <summary>The user revoked one of their sessions (DELETE /auth/sessions/{id}).</summary>
    SessionRevoked,

    /// <summary>A rotated refresh token was replayed: the family was revoked as stolen.</summary>
    TokenReuse,

    /// <summary>Password changed or reset: every family of the user was revoked.</summary>
    PasswordChange,

    /// <summary>An application asked to end the user's sessions with it (RP-initiated logout, /oauth/logout).</summary>
    ApplicationLogout,

    /// <summary>
    /// An administrator removed a role or a role's permission (every family of the affected users was revoked, scope All),
    /// or deleted an application role (that application's families of its holders, scope Application, T30).
    /// </summary>
    AdminRevoked,

    /// <summary>An application was deactivated, or its audience changed: every family issued to it was revoked.</summary>
    ApplicationDeactivated,

    /// <summary>A used authorization code was presented again: the family it started was revoked.</summary>
    CodeReplay,

    /// <summary>The email was verified and the pending password took effect: every family of the user was revoked.</summary>
    EmailVerified,

    /// <summary>A refresh found the account disabled or unverified: the family was revoked.</summary>
    AccountDisabled,

    /// <summary>MFA was turned on (T21): every session of the user, opened with the password alone, was revoked.</summary>
    MfaEnrolled,

    /// <summary>The user turned MFA off with their factors: every session was revoked.</summary>
    MfaDisabled,

    /// <summary>An administrator reset the user's MFA: every session was revoked.</summary>
    MfaReset,
}

/// <summary>Which sessions an event is about, stated by the publisher (never inferred by a listener).</summary>
public enum SessionEndScope
{
    /// <summary>A browser session of <see cref="SessionEnded.UserId"/> (single logout cascades to every application session).</summary>
    Browser = 1,

    /// <summary>
    /// Sessions at <see cref="SessionEnded.ClientApplicationId"/>: one family, the user's sessions there, every user's
    /// (UserId null, deactivation), or every holder's of <see cref="SessionEnded.RoleId"/> (an application role deleted).
    /// Never cascades.
    /// </summary>
    Application,

    /// <summary>Every session of the user, or of every holder of <see cref="SessionEnded.RoleId"/> (UserId null). Never cascades.</summary>
    All,
}

/// <summary>
/// One ending of sessions. <see cref="UserId"/> null means every affected user (application deactivation, a role's
/// holders); <see cref="FamilyId"/> null means every family in scope. Published by the path that ends the sessions;
/// for <see cref="SessionEndScope.Browser"/> and <see cref="SessionEndCause.ApplicationLogout"/> BEFORE that path
/// revokes the browser family (so a listener failure leaves the browser session usable to retry), otherwise after.
/// </summary>
public sealed record SessionEnded(
    SessionEndScope Scope,
    SessionEndCause Cause,
    Guid? UserId,
    Guid? FamilyId = null,
    Guid? ClientApplicationId = null,
    Guid? RoleId = null);

/// <summary>
/// Reacts to ended sessions (T20 fan-out hook). Listeners run in DI registration order (SingleLogoutListener first); a
/// failure propagates. Back-channel notification of applications (later, needs a schema change) is one more listener.
/// </summary>
public interface ISessionEndedListener
{
    Task OnSessionEndedAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken);
}

/// <summary>Publishes <see cref="SessionEnded"/> to every registered <see cref="ISessionEndedListener"/>, in registration order.</summary>
public interface ISessionEndedPublisher
{
    /// <exception cref="SessionEndFailedException">A listener failed (the original exception is the inner one).</exception>
    Task PublishAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken);
}

/// <summary>A session-ended listener failed: the sign-out is incomplete on the server and can be retried.</summary>
public sealed class SessionEndFailedException(Exception inner)
    : Exception("A session-ended listener failed: " + inner.GetType().Name, inner);

internal sealed class SessionEndedPublisher(IEnumerable<ISessionEndedListener> listeners) : ISessionEndedPublisher
{
    public async Task PublishAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ended);
        ArgumentNullException.ThrowIfNull(audit);
        foreach (ISessionEndedListener listener in listeners)
        {
            try
            {
                await listener.OnSessionEndedAsync(ended, audit, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not SessionEndFailedException)
            {
                throw new SessionEndFailedException(ex);
            }
        }
    }
}

/// <summary>
/// Single logout (T20), the one owner of application-session endings caused by the user and of the SingleLogout audit:
/// <list type="bullet">
/// <item><b>Browser scope</b>: every application session of the user ends (application families are started from a
/// browser session, and no link records which one; that would be a schema change).</item>
/// <item><b>ApplicationLogout</b>: the user's sessions at that application end; the browser and other applications stay.</item>
/// <item>Any other event: the publisher already revoked everything in scope; nothing to cascade.</item>
/// </list>
/// What it revokes it also drops from the live-session cache. Audited SingleLogout with the cause and the count.
/// Application access tokens are bearer tokens checked by resource servers: they stay valid until they expire.
/// </summary>
internal sealed class SingleLogoutListener(
    IRefreshTokenRepository refreshRows,
    ISessionLiveness liveness,
    IAuditService audits,
    IClock clock) : ISessionEndedListener
{
    public async Task OnSessionEndedAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ended);
        bool applicationLogout = ended.Cause == SessionEndCause.ApplicationLogout;
        if ((ended.Scope != SessionEndScope.Browser && !applicationLogout) || ended.UserId is not Guid userId)
        {
            return;
        }

        if (applicationLogout && ended.ClientApplicationId is null)
        {
            throw new ArgumentException("An application logout names its application.", nameof(ended));
        }

        int revoked = await refreshRows.RevokeApplicationFamiliesForUserAsync(
            userId, applicationLogout ? ended.ClientApplicationId : null, RevokedReason(ended.Cause), clock.UtcNow, cancellationToken);
        if (revoked > 0)
        {
            liveness.InvalidateUser(userId);
        }

        if (revoked > 0 || applicationLogout)
        {
            await audits.TryWriteAsync(AuditEvents.SingleLogout(userId, applicationLogout ? ended.ClientApplicationId : null, ended.Cause, revoked), audit, cancellationToken);
        }
    }

    /// <summary>The RefreshToken.RevokedReason for a cascading cause; an unmapped cause is a programming error, never a silent Logout.</summary>
    internal static string RevokedReason(SessionEndCause cause) => cause switch
    {
        SessionEndCause.Logout or SessionEndCause.SessionRevoked or SessionEndCause.ApplicationLogout => RefreshTokenRevokedReason.Logout,
        SessionEndCause.TokenReuse => RefreshTokenRevokedReason.Reuse,
        SessionEndCause.AccountDisabled => RefreshTokenRevokedReason.Admin,
        _ => throw new ArgumentOutOfRangeException(nameof(cause), cause, "This cause never cascades to application sessions."),
    };
}
