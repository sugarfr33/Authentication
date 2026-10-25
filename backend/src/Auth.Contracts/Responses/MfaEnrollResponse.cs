using System.Text.Json.Serialization;

namespace Auth.Contracts.Responses;

/// <summary>
/// MFA enrollment (T21), shown once: the otpauth URI for a QR code and the same key for manual entry. Nothing is stored
/// in plain form; recovery codes come with the confirmation (<see cref="MfaRecoveryCodesResponse"/>).
/// </summary>
public sealed record MfaEnrollResponse(string OtpAuthUri, string ManualEntryKey);

/// <summary>The 10 recovery codes, shown once (confirmation or regeneration); only their keyed hashes are stored.</summary>
public sealed record MfaRecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes);

/// <summary>Password accepted, second factor needed: the challenge is in the HttpOnly __Secure-mfa cookie, never in a body.</summary>
public sealed record MfaRequiredResponse([property: JsonPropertyName("mfa_required")] bool MfaRequired);
