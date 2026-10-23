namespace Auth.Contracts.Responses;

/// <summary>MFA enrolment data. The recovery codes are shown once and only their hashes are stored.</summary>
public sealed record MfaEnrollResponse(string OtpAuthUri, IReadOnlyList<string> RecoveryCodes);
