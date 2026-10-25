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
    MfaEnabled,
    MfaVerified,
    MfaFailed,
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
}
