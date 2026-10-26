using System.Text.Json;

namespace Auth.Contracts.Responses;

// Admin API read models (T21b). Account fields only: never a password hash, MFA secret, recovery code, security stamp
// or token (ResponseDtoTests scans these names).

/// <summary>One account in the admin list.</summary>
public sealed record AdminUserSummary(
    Guid Id,
    string Email,
    string DisplayName,
    bool EmailVerified,
    bool IsActive,
    bool MfaEnabled,
    bool LockedOut,
    DateTime CreatedUtc,
    DateTime? LastLoginUtc);

/// <summary>A page of accounts; <c>Total</c> counts every match of the filter.</summary>
public sealed record AdminUserPage(IReadOnlyList<AdminUserSummary> Items, int Page, int PageSize, int Total);

/// <summary>A role reference: global when <c>ClientId</c> is null, otherwise scoped to that application.</summary>
public sealed record AdminRoleReference(Guid Id, string Name, string? ClientId);

/// <summary>One account with its roles and the number of its live sessions (browser and application).</summary>
public sealed record AdminUserDetail(AdminUserSummary User, IReadOnlyList<AdminRoleReference> Roles, int ActiveSessions);

public sealed record AdminPermissionInfo(Guid Id, string Code, string? Description);

public sealed record AdminRoleInfo(
    Guid Id,
    string Name,
    string? ClientId,
    bool IsSystem,
    string? Description,
    IReadOnlyList<AdminPermissionInfo> Permissions);

/// <summary>
/// One audit row (audit.read only). <c>Detail</c> is the stored detail object (catalogue keys and words only). It can
/// name real failure reasons, which is why this read model is never returned by any other endpoint.
/// </summary>
public sealed record AdminAuditEntry(
    long Id,
    DateTime OccurredUtc,
    string EventType,
    Guid? UserId,
    Guid? ClientApplicationId,
    string? IpAddress,
    string? UserAgent,
    string? CorrelationId,
    JsonElement? Detail);

/// <summary>Newest first; pass <c>NextBefore</c> as <c>before</c> to get the next page (null on the last one).</summary>
public sealed record AdminAuditPage(IReadOnlyList<AdminAuditEntry> Items, long? NextBefore);
