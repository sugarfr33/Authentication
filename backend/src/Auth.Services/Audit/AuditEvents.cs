using Auth.Contracts;

namespace Auth.Services.Audit;

/// <summary>
/// The only way to build an <see cref="AuditEvent"/>: one factory per written event type, named after it, with typed
/// arguments. Reserved catalogue types have no factory (a test checks both directions).
/// </summary>
internal static class AuditEvents
{
    /// <summary>A new account was created (pending verification).</summary>
    public static AuditEvent Registered(Guid userId) => new(AuditEventType.Registered, userId, new AuditField("outcome", "created"));

    /// <summary>A sign-up for an existing account (high volume, short retention).</summary>
    public static AuditEvent RegistrationDuplicate(Guid userId) => new(AuditEventType.RegistrationDuplicate, userId);

    public static AuditEvent EmailVerified(Guid userId) => new(AuditEventType.EmailVerified, userId);

    public static AuditEvent EmailVerificationFailed(Guid? userId, string reason) =>
        new(AuditEventType.EmailVerificationFailed, userId, new AuditField("reason", reason));

    /// <summary>Holds the failing field names only, never their values.</summary>
    public static AuditEvent RegistrationRejected(IEnumerable<string> fields) =>
        new(AuditEventType.RegistrationRejected, null, new AuditField("fields", fields.Order(StringComparer.Ordinal).ToArray()));

    public static AuditEvent LoginSucceeded(Guid userId) => new(AuditEventType.LoginSucceeded, userId);

    public static AuditEvent LoginFailed(Guid? userId, string reason) => new(AuditEventType.LoginFailed, userId, new AuditField("reason", reason));

    public static AuditEvent Lockout(Guid userId, DateTime untilUtc, int level) =>
        new(AuditEventType.Lockout, userId, new AuditField("until", untilUtc), new AuditField("level", level));

    public static AuditEvent Logout(Guid userId, int revoked) => new(AuditEventType.Logout, userId, new AuditField("revoked", revoked));

    public static AuditEvent LogoutAll(Guid userId, int revoked) => new(AuditEventType.LogoutAll, userId, new AuditField("revoked", revoked));

    public static AuditEvent TokenRefreshed(Guid userId) => new(AuditEventType.TokenRefreshed, userId);

    public static AuditEvent TokenReuse(Guid userId, int revoked) => new(AuditEventType.TokenReuse, userId, new AuditField("revoked", revoked));

    /// <summary>A refresh refused after the token was found; <paramref name="applicationId"/> for an application family.</summary>
    public static AuditEvent RefreshRejected(Guid userId, string reason, Guid? applicationId = null) => applicationId is Guid app
        ? new(AuditEventType.RefreshRejected, userId, new AuditField("reason", reason), new AuditField("app", app))
        : new(AuditEventType.RefreshRejected, userId, new AuditField("reason", reason));

    /// <summary>A session ended by its owner (no reason) or by the server (reason, e.g. session_cap).</summary>
    public static AuditEvent SessionRevoked(Guid userId, Guid session, string? reason = null) => reason is null
        ? new(AuditEventType.SessionRevoked, userId, new AuditField("session", session))
        : new(AuditEventType.SessionRevoked, userId, new AuditField("session", session), new AuditField("reason", reason));

    public static AuditEvent PasswordResetRequested(Guid? userId, string outcome) =>
        new(AuditEventType.PasswordResetRequested, userId, new AuditField("outcome", outcome));

    public static AuditEvent PasswordReset(Guid userId) => new(AuditEventType.PasswordReset, userId);

    public static AuditEvent PasswordResetFailed(Guid? userId, string reason) =>
        new(AuditEventType.PasswordResetFailed, userId, new AuditField("reason", reason));

    public static AuditEvent PasswordChanged(Guid userId) => new(AuditEventType.PasswordChanged, userId);

    public static AuditEvent PasswordChangeFailed(Guid? userId, string reason) =>
        new(AuditEventType.PasswordChangeFailed, userId, new AuditField("reason", reason));

    /// <summary>A system role given by the server (<paramref name="source"/>: bootstrap or backfill).</summary>
    public static AuditEvent RoleAssigned(Guid userId, string role, string source) =>
        new(AuditEventType.RoleAssigned, userId, new AuditField("role", role), new AuditField("source", source));

    public static AuditEvent RoleRemoved(Guid userId, Guid roleId) => new(AuditEventType.RoleRemoved, userId, new AuditField("role", roleId));

    /// <summary>A client application was registered (<paramref name="source"/>: registry or bootstrap).</summary>
    public static AuditEvent AppCreated(Guid applicationId, string source, bool requireRole = false) =>
        new(AuditEventType.AppCreated, null, new AuditField("app", applicationId), new AuditField("source", source), new AuditField("requireRole", requireRole));

    /// <summary>Settings changed or activated; <paramref name="revoked"/> is set when an audience change ended its sessions.</summary>
    /// <param name="requireRole">The RequireRole setting after a settings change (T30); null for an activation.</param>
    public static AuditEvent AppUpdated(Guid applicationId, bool active, int? revoked = null, bool? requireRole = null) =>
        new(
            AuditEventType.AppUpdated,
            null,
            [
                new AuditField("app", applicationId),
                new AuditField("active", active),
                .. revoked is int count ? [new AuditField("revoked", count)] : Array.Empty<AuditField>(),
                .. requireRole is bool flag ? [new AuditField("requireRole", flag)] : Array.Empty<AuditField>(),
            ]);

    public static AuditEvent AppDeactivated(Guid applicationId, int revoked) =>
        new(AuditEventType.AppDeactivated, null, new AuditField("app", applicationId), new AuditField("revoked", revoked));

    /// <summary>A code was issued to a signed-in user for the application (never the code itself).</summary>
    public static AuditEvent AuthorizationCodeIssued(Guid userId, Guid applicationId) =>
        new(AuditEventType.AuthorizationCodeIssued, userId, new AuditField("app", applicationId));

    /// <summary>A code was exchanged; <paramref name="session"/> is the refresh family it started.</summary>
    public static AuditEvent AuthorizationCodeRedeemed(Guid userId, Guid applicationId, Guid session) =>
        new(AuditEventType.AuthorizationCodeRedeemed, userId, new AuditField("app", applicationId), new AuditField("session", session));

    /// <summary>MFA turned on or its recovery codes changed: action enrolled or regenerated. Never a code or secret.</summary>
    public static AuditEvent MfaEnabled(Guid userId, string action) => new(AuditEventType.MfaEnabled, userId, new AuditField("action", action));

    /// <summary>An MFA enrollment started (a pending secret was shown once). Never the secret.</summary>
    public static AuditEvent MfaEnrollmentStarted(Guid userId) => new(AuditEventType.MfaEnrollmentStarted, userId);

    /// <summary>MFA turned off: action disabled (by the user, with factors) or reset (by an administrator).</summary>
    public static AuditEvent MfaDisabled(Guid userId, string action) => new(AuditEventType.MfaDisabled, userId, new AuditField("action", action));

    /// <summary>A sign-in passed the TOTP second factor.</summary>
    public static AuditEvent MfaVerified(Guid userId) => new(AuditEventType.MfaVerified, userId);

    /// <summary>A wrong or unusable second factor (or password at an MFA step); the reason word only.</summary>
    public static AuditEvent MfaFailed(Guid? userId, string reason) => new(AuditEventType.MfaFailed, userId, new AuditField("reason", reason));

    /// <summary>A sign-in used one recovery code.</summary>
    public static AuditEvent MfaRecoveryCodeUsed(Guid userId) => new(AuditEventType.MfaRecoveryCodeUsed, userId);

    /// <summary>Single logout: application sessions ended; <paramref name="applicationId"/> when an application asked.</summary>
    public static AuditEvent SingleLogout(Guid userId, Guid? applicationId, Auth.Services.Security.SessionEndCause cause, int revoked) => applicationId is Guid app
        ? new(AuditEventType.SingleLogout, userId, new AuditField("cause", CauseWord(cause)), new AuditField("revoked", revoked), new AuditField("app", app))
        : new(AuditEventType.SingleLogout, userId, new AuditField("cause", CauseWord(cause)), new AuditField("revoked", revoked));

    /// <summary>The audit word of a cause: its name in lower-case snake_case (in the catalogue's word list).</summary>
    internal static string CauseWord(Auth.Services.Security.SessionEndCause cause) => cause switch
    {
        Auth.Services.Security.SessionEndCause.Logout => "logout",
        Auth.Services.Security.SessionEndCause.LogoutAll => "logout_all",
        Auth.Services.Security.SessionEndCause.SessionRevoked => "session_revoked",
        Auth.Services.Security.SessionEndCause.TokenReuse => "token_reuse",
        Auth.Services.Security.SessionEndCause.PasswordChange => "password_change",
        Auth.Services.Security.SessionEndCause.ApplicationLogout => "application_logout",
        Auth.Services.Security.SessionEndCause.AdminRevoked => "admin_revoked",
        Auth.Services.Security.SessionEndCause.ApplicationDeactivated => "application_deactivated",
        Auth.Services.Security.SessionEndCause.CodeReplay => "code_replay",
        Auth.Services.Security.SessionEndCause.EmailVerified => "email_verified",
        Auth.Services.Security.SessionEndCause.AccountDisabled => "account_disabled",
        Auth.Services.Security.SessionEndCause.MfaEnrolled => "mfa_enrolled",
        Auth.Services.Security.SessionEndCause.MfaDisabled => "mfa_disabled",
        Auth.Services.Security.SessionEndCause.MfaReset => "mfa_reset",
        _ => throw new ArgumentOutOfRangeException(nameof(cause), cause, "Unmapped session end cause."),
    };

    public static AuditEvent AuthorizationCodeRejected(Guid? userId, Guid? applicationId, string reason) => applicationId is Guid app
        ? new(AuditEventType.AuthorizationCodeRejected, userId, new AuditField("app", app), new AuditField("reason", reason))
        : new(AuditEventType.AuthorizationCodeRejected, userId, new AuditField("reason", reason));

    public static AuditEvent RolePermissionRemoved(Guid roleId, Guid permissionId) =>
        new(AuditEventType.RolePermissionRemoved, null, new AuditField("role", roleId), new AuditField("permission", permissionId));

    /// <summary>A role given by an administrator (T21b): the role id, source "admin"; the actor comes from the audit context.</summary>
    public static AuditEvent RoleAssigned(Guid userId, Guid roleId, string source) =>
        new(AuditEventType.RoleAssigned, userId, new AuditField("role", roleId), new AuditField("source", source));

    public static AuditEvent RolePermissionGranted(Guid roleId, Guid permissionId) =>
        new(AuditEventType.RolePermissionGranted, null, new AuditField("role", roleId), new AuditField("permission", permissionId));

    public static AuditEvent UserDeactivated(Guid userId, int revoked) =>
        new(AuditEventType.UserDeactivated, userId, new AuditField("revoked", revoked));

    public static AuditEvent UserReactivated(Guid userId) => new(AuditEventType.UserReactivated, userId);

    /// <summary>A signing key was added (T29): kid, algorithm word and activation time; never the secret reference.</summary>
    /// <summary>T30 fix (audit L2): the name and client id are kept so a deleted role stays identifiable.</summary>
    public static AuditEvent RoleCreated(Guid roleId, string name, Guid applicationId, string clientId) =>
        new(AuditEventType.RoleCreated, null, new AuditField("role", roleId), new AuditField("name", new AuditPlainId(name)),
            new AuditField("app", applicationId), new AuditField("clientId", new AuditPlainId(clientId, ClientIdMaxLength)));

    /// <param name="revoked">Refresh tokens of the role's holders at this application that were revoked.</param>
    public static AuditEvent RoleDeleted(Guid roleId, string name, Guid applicationId, string clientId, int revoked) =>
        new(AuditEventType.RoleDeleted, null, new AuditField("role", roleId), new AuditField("name", new AuditPlainId(name)),
            new AuditField("app", applicationId), new AuditField("clientId", new AuditPlainId(clientId, ClientIdMaxLength)), new AuditField("revoked", revoked));

    /// <summary>Client ids are 3 to 100 characters (ClientApplicationValidator).</summary>
    private const int ClientIdMaxLength = 100;

    public static AuditEvent SigningKeyAdded(string kid, string algorithm, DateTime activatesUtc) =>
        new(AuditEventType.SigningKeyAdded, null, new AuditField("kid", new AuditPlainId(kid)), new AuditField("algorithm", algorithm), new AuditField("activates", activatesUtc));
}
