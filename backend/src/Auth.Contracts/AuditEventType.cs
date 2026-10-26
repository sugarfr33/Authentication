namespace Auth.Contracts;

/// <summary>Security events written to the audit log; stored by name in <c>AuditLog.EventType</c>.</summary>
public enum AuditEventType
{
    Registered = 1,
    EmailVerified,
    LoginSucceeded,
    LoginFailed,
    Lockout,
    Logout,
    LogoutAll,
    TokenRefreshed,
    TokenReuse,
    SessionRevoked,
    PasswordResetRequested,
    PasswordReset,
    PasswordChanged,
    /// <summary>MFA turned on (enrollment confirmed) or its recovery codes regenerated (an action word only).</summary>
    MfaEnabled,

    /// <summary>A sign-in passed the TOTP second factor.</summary>
    MfaVerified,

    /// <summary>A wrong or unusable second factor; a reason word only.</summary>
    MfaFailed,

    /// <summary>A sign-in used a recovery code.</summary>
    MfaRecoveryCodeUsed,
    AuthorizationCodeIssued,
    AuthorizationCodeRedeemed,
    SigningKeyRotated,

    /// <summary>A verify-email attempt failed (unknown, used, expired or unusable link). Never holds the token.</summary>
    EmailVerificationFailed,

    /// <summary>A sign-up was rejected by validation. Holds the failing field names only, never their values.</summary>
    RegistrationRejected,

    /// <summary>A reset-password attempt failed (bad link or rejected new password). Never holds the token or a password.</summary>
    PasswordResetFailed,

    /// <summary>A change-password attempt failed (wrong current password or rejected new password). Never holds a password.</summary>
    PasswordChangeFailed,

    /// <summary>
    /// A refresh was refused without theft signs: a token of an already ended session was replayed (logout, password
    /// change, revoked session), or the session changed while refreshing. Holds a reason only.
    /// </summary>
    RefreshRejected,

    /// <summary>A role was given to a user (also the bootstrap administrator). Holds the role name and the source.</summary>
    RoleAssigned,

    /// <summary>A role was taken from a user; the user's sessions were ended. Holds the role name.</summary>
    RoleRemoved,

    /// <summary>A permission was taken from a role; the sessions of every holder were ended. Holds role and permission.</summary>
    RolePermissionRemoved,

    /// <summary>
    /// A sign-up for an email that already has an account (the owner was emailed). High volume: anyone can cause it, so
    /// it is kept apart from Registered (new accounts) and gets the short retention.
    /// </summary>
    RegistrationDuplicate,

    /// <summary>A client application was registered. Holds its id and the source (bootstrap when seeded).</summary>
    AppCreated,

    /// <summary>A client application's settings changed, or it was activated again. Holds its id and active flag.</summary>
    AppUpdated,

    /// <summary>A client application was deactivated; its sessions were ended. Holds its id and the revoked count.</summary>
    AppDeactivated,

    /// <summary>An authorization code exchange or app refresh was refused. Holds the app id when known and a reason only.</summary>
    AuthorizationCodeRejected,

    /// <summary>
    /// Single logout (T20): application sessions ended because a browser session ended, or an application asked to end
    /// the user's sessions with it. Holds the cause, the number of tokens revoked and the app id when one asked.
    /// </summary>
    SingleLogout,

    /// <summary>MFA enrollment started (a pending secret was shown; MFA is not on yet).</summary>
    MfaEnrollmentStarted,

    /// <summary>MFA turned off by the user (action disabled) or by an administrator (action reset).</summary>
    MfaDisabled,

    /// <summary>An administrator deactivated the account; every session ended (T21b).</summary>
    UserDeactivated,

    /// <summary>An administrator reactivated the account (T21b).</summary>
    UserReactivated,

    /// <summary>An administrator granted a permission to a role (T21b).</summary>
    RolePermissionGranted,
}
