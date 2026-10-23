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
}
