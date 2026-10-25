using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;

namespace Auth.Services.Security;

/// <summary>Why sessions ended. The audit words are the lower-case snake_case names.</summary>
public enum SessionEndCause
{
    /// <summary>The browser signed out (POST /auth/logout).</summary>
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
}

/// <summary>
/// One ending of sessions, after the revocation is committed: <see cref="FamilyId"/> for one family (null: all of the
/// user's families in scope), <see cref="ClientApplicationId"/> for an application's session(s) (null: a browser
/// session, or every session for LogoutAll and PasswordChange).
/// </summary>
public sealed record SessionEnded(Guid UserId, Guid? FamilyId, Guid? ClientApplicationId, SessionEndCause Cause);

/// <summary>
/// Reacts to ended sessions (T20 fan-out hook). Listeners run in registration order, after the revocation that caused
/// the event; a listener failure propagates, so the caller reports the sign-out as incomplete instead of claiming it.
/// Back-channel notification of applications (a later task, needs a schema change) is one more listener.
/// </summary>
public interface ISessionEndedListener
{
    Task OnSessionEndedAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken);
}

/// <summary>Publishes <see cref="SessionEnded"/> to every registered <see cref="ISessionEndedListener"/>.</summary>
public interface ISessionEndedPublisher
{
    Task PublishAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class SessionEndedPublisher(IEnumerable<ISessionEndedListener> listeners) : ISessionEndedPublisher
{
    public async Task PublishAsync(SessionEnded ended, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ended);
        ArgumentNullException.ThrowIfNull(audit);
        foreach (ISessionEndedListener listener in listeners)
        {
            await listener.OnSessionEndedAsync(ended, audit, cancellationToken);
        }
    }
}

/// <summary>
/// Single logout (T20): when a BROWSER session ends by the user's action (logout, logout-all, revoking a session, a
/// detected token theft, a password change), every application session of that user ends too: application families are
/// started from a browser session, and no link records which one (that would be a schema change), so all of them go.
/// The user's live-session cache entries are dropped on this instance. Application access tokens are bearer tokens
/// checked by resource servers, so they stay valid until they expire (at most the access-token lifetime, 15 min).
/// Audited SingleLogout with the cause and the number of tokens revoked (only when something was revoked).
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
        liveness.InvalidateUser(ended.UserId);
        if (ended.ClientApplicationId is not null || ended.Cause == SessionEndCause.ApplicationLogout)
        {
            // An application's own session ended: the browser session and the other applications stay.
            return;
        }

        string reason = ended.Cause switch
        {
            SessionEndCause.LogoutAll => RefreshTokenRevokedReason.LogoutAll,
            SessionEndCause.PasswordChange => RefreshTokenRevokedReason.PasswordChange,
            SessionEndCause.TokenReuse => RefreshTokenRevokedReason.Reuse,
            _ => RefreshTokenRevokedReason.Logout,
        };
        int revoked = await refreshRows.RevokeApplicationFamiliesForUserAsync(ended.UserId, null, reason, clock.UtcNow, cancellationToken);
        if (revoked > 0)
        {
            await audits.TryWriteAsync(AuditEvents.SingleLogout(ended.UserId, null, ended.Cause, revoked), audit, cancellationToken);
        }
    }
}
