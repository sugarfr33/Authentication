namespace Auth.Contracts.Requests;

/// <summary>Self-service sign-up.</summary>
public sealed record RegisterRequest(string Email, string Password, string DisplayName);

/// <summary>Email and password sign-in, optionally on behalf of a client application.</summary>
public sealed record LoginRequest(string Email, string Password, string? ClientId);

/// <summary>Starts a password reset. The response is identical whether or not the email exists.</summary>
public sealed record ForgotPasswordRequest(string Email);

/// <summary>Completes a password reset with the raw token from the reset email.</summary>
public sealed record ResetPasswordRequest(string Token, string NewPassword);

/// <summary>Password change by a signed-in user.</summary>
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

/// <summary>Confirms an email address with the raw token from the verification email.</summary>
public sealed record VerifyEmailRequest(string Token);

/// <summary>Second factor: a TOTP code, or a recovery code when <paramref name="IsRecoveryCode"/> is true.</summary>
public sealed record MfaVerifyRequest(string Code, bool IsRecoveryCode);
