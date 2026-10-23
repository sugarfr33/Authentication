namespace Auth.Contracts;

/// <summary>Expected failures returned by services through <see cref="Result"/>; never thrown.</summary>
public enum AuthError
{
    /// <summary>Unknown email, wrong password or inactive account; deliberately indistinguishable.</summary>
    GenericInvalidCredentials = 1,
    LockedOut,
    EmailNotVerified,
    MfaRequired,
    InvalidMfaCode,
    InvalidOrExpiredToken,
    TokenReuseDetected,
    ConcurrentRotation,
    PasswordPolicyViolation,
    ValidationFailed,
    InvalidClient,
    InvalidRedirectUri,
    InvalidGrant,
    NotFound,
    Forbidden,
}
