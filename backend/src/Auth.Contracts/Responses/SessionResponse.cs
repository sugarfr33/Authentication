namespace Auth.Contracts.Responses;

/// <summary>One active session (refresh-token family) of the signed-in user.</summary>
public sealed record SessionResponse(
    Guid FamilyId,
    string Ip,
    string UserAgent,
    DateTime CreatedUtc,
    DateTime LastUsedUtc,
    bool IsCurrent);
