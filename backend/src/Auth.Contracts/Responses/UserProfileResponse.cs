namespace Auth.Contracts.Responses;

/// <summary>The signed-in user as returned by <c>/auth/me</c>.</summary>
public sealed record UserProfileResponse(
    Guid Id,
    string Email,
    bool EmailVerified,
    string DisplayName,
    bool MfaEnabled,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions);
