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
}
