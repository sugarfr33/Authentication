using Auth.Contracts;

namespace Auth.Services.Audit;

/// <summary>
/// The only way to build an <see cref="AuditEvent"/>: one factory per written event type, named after it, with typed
/// arguments. Reserved catalogue types have no factory (a test checks both directions).
/// </summary>
internal static class AuditEvents
{
    /// <summary>A new account was created (pending verification).</summary>
    public static AuditEvent Registered(Guid userId) => new(AuditEventType.Registered, userId, new AuditField("outcome", "created"));

    /// <summary>A sign-up for an existing account (high volume, short retention).</summary>
    public static AuditEvent RegistrationDuplicate(Guid userId) => new(AuditEventType.RegistrationDuplicate, userId);

    public static AuditEvent EmailVerified(Guid userId) => new(AuditEventType.EmailVerified, userId);

    public static AuditEvent EmailVerificationFailed(Guid? userId, string reason) =>
        new(AuditEventType.EmailVerificationFailed, userId, new AuditField("reason", reason));

    /// <summary>Holds the failing field names only, never their values.</summary>
    public static AuditEvent RegistrationRejected(IEnumerable<string> fields) =>
        new(AuditEventType.RegistrationRejected, null, new AuditField("fields", fields.Order(StringComparer.Ordinal).ToArray()));

    public static AuditEvent LoginSucceeded(Guid userId) => new(AuditEventType.LoginSucceeded, userId);

    public static AuditEvent LoginFailed(Guid? userId, string reason) => new(AuditEventType.LoginFailed, userId, new AuditField("reason", reason));

    public static AuditEvent Lockout(Guid userId, DateTime untilUtc, int level) =>
        new(AuditEventType.Lockout, userId, new AuditField("until", untilUtc), new AuditField("level", level));

    public static AuditEvent Logout(Guid userId, int revoked) => new(AuditEventType.Logout, userId, new AuditField("revoked", revoked));

    public static AuditEvent LogoutAll(Guid userId, int revoked) => new(AuditEventType.LogoutAll, userId, new AuditField("revoked", revoked));

    public static AuditEvent TokenRefreshed(Guid userId) => new(AuditEventType.TokenRefreshed, userId);

    public static AuditEvent TokenReuse(Guid userId, int revoked) => new(AuditEventType.TokenReuse, userId, new AuditField("revoked", revoked));

    public static AuditEvent RefreshRejected(Guid userId, string reason) => new(AuditEventType.RefreshRejected, userId, new AuditField("reason", reason));

    /// <summary>A session ended by its owner (no reason) or by the server (reason, e.g. session_cap).</summary>
    public static AuditEvent SessionRevoked(Guid userId, Guid session, string? reason = null) => reason is null
        ? new(AuditEventType.SessionRevoked, userId, new AuditField("session", session))
        : new(AuditEventType.SessionRevoked, userId, new AuditField("session", session), new AuditField("reason", reason));

    public static AuditEvent PasswordResetRequested(Guid? userId, string outcome) =>
        new(AuditEventType.PasswordResetRequested, userId, new AuditField("outcome", outcome));

    public static AuditEvent PasswordReset(Guid userId) => new(AuditEventType.PasswordReset, userId);

    public static AuditEvent PasswordResetFailed(Guid? userId, string reason) =>
        new(AuditEventType.PasswordResetFailed, userId, new AuditField("reason", reason));

    public static AuditEvent PasswordChanged(Guid userId) => new(AuditEventType.PasswordChanged, userId);

    public static AuditEvent PasswordChangeFailed(Guid? userId, string reason) =>
        new(AuditEventType.PasswordChangeFailed, userId, new AuditField("reason", reason));

    /// <summary>A system role given by the server (<paramref name="source"/>: bootstrap or backfill).</summary>
    public static AuditEvent RoleAssigned(Guid userId, string role, string source) =>
        new(AuditEventType.RoleAssigned, userId, new AuditField("role", role), new AuditField("source", source));

    public static AuditEvent RoleRemoved(Guid userId, Guid roleId) => new(AuditEventType.RoleRemoved, userId, new AuditField("role", roleId));

    public static AuditEvent RolePermissionRemoved(Guid roleId, Guid permissionId) =>
        new(AuditEventType.RolePermissionRemoved, null, new AuditField("role", roleId), new AuditField("permission", permissionId));
}
