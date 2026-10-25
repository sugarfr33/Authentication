using Auth.Entities;

namespace Auth.DAL.Repositories;

// Conventions for every repository:
// - Entities returned are tracked by the scope's context; changes are persisted by IUnitOfWork.SaveChangesAsync.
// - AddAsync only stages the entity; nothing is written until SaveChangesAsync.
// - Methods returning a row count are single set-based statements that run immediately (inside the current
//   IUnitOfWork transaction, if one is open) and bypass the change tracker.
// - No business rules: callers pass in the current time and the reason; repositories only filter and persist.

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken);

    Task<User?> GetByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken);

    Task AddAsync(User user, CancellationToken cancellationToken);

    /// <summary>
    /// Attaches a <b>detached</b> user (one not loaded in this scope) and marks every column modified.
    /// Only for detached entities: entities returned by this repository are already tracked, so just change them and
    /// call <see cref="Auth.DAL.IUnitOfWork.SaveChangesAsync"/>. Calling Update on a tracked entity is unnecessary,
    /// and calling it with a second instance of an already-tracked row throws.
    /// </summary>
    void Update(User user);
}

public interface IRoleRepository
{
    /// <summary>Global roles plus, when <paramref name="clientApplicationId"/> is given, that application's roles.</summary>
    Task<IReadOnlyList<Role>> GetForUserAsync(Guid userId, Guid? clientApplicationId, CancellationToken cancellationToken);

    /// <summary>Distinct permission codes granted by the roles <see cref="GetForUserAsync"/> returns.</summary>
    Task<IReadOnlyList<string>> GetPermissionCodesForUserAsync(Guid userId, Guid? clientApplicationId, CancellationToken cancellationToken);

    /// <summary>Every permission row (tracked).</summary>
    Task<IReadOnlyList<Permission>> GetPermissionsAsync(CancellationToken cancellationToken);

    Task AddPermissionAsync(Permission permission, CancellationToken cancellationToken);

    /// <summary>The global role (no client application) with this normalized name, or null.</summary>
    Task<Role?> GetGlobalRoleAsync(string normalizedName, CancellationToken cancellationToken);

    Task AddRoleAsync(Role role, CancellationToken cancellationToken);

    /// <summary>Ids of the permissions granted to the role.</summary>
    Task<IReadOnlyList<Guid>> GetPermissionIdsOfRoleAsync(Guid roleId, CancellationToken cancellationToken);

    Task AddRolePermissionAsync(RolePermission grant, CancellationToken cancellationToken);

    Task<bool> UserHasRoleAsync(Guid userId, Guid roleId, CancellationToken cancellationToken);

    Task AddUserRoleAsync(UserRole assignment, CancellationToken cancellationToken);

    /// <summary>True when at least one active user with a verified email holds the role.</summary>
    Task<bool> AnyActiveVerifiedHolderAsync(Guid roleId, CancellationToken cancellationToken);

    /// <summary>Ids of active, verified users who do not hold the role, at most <paramref name="max"/>.</summary>
    Task<IReadOnlyList<Guid>> GetActiveVerifiedUsersWithoutRoleAsync(Guid roleId, int max, CancellationToken cancellationToken);

    /// <summary>Deletes the user's assignment of the role in one DELETE. Returns the number of rows deleted (0 or 1).</summary>
    Task<int> RemoveUserRoleAsync(Guid userId, Guid roleId, CancellationToken cancellationToken);

    /// <summary>Deletes the role's grant of the permission in one DELETE. Returns the number of rows deleted (0 or 1).</summary>
    Task<int> RemoveRolePermissionAsync(Guid roleId, Guid permissionId, CancellationToken cancellationToken);
}

/// <summary>
/// Read model of one live session (refresh family): when it started (its first token), when it was last refreshed (its
/// live token), and the IP and user agent of that last refresh. No hashes, tokens or row ids.
/// </summary>
public interface IRefreshSessionSummary
{
    Guid FamilyId { get; }

    DateTime CreatedUtc { get; }

    DateTime LastUsedUtc { get; }

    string IpAddress { get; }

    string UserAgent { get; }

    /// <summary>The client application of the family; null for a browser session.</summary>
    Guid? ClientApplicationId { get; }
}

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetByHashAsync(byte[] tokenHash, CancellationToken cancellationToken);

    /// <summary>
    /// Like <see cref="GetByHashAsync"/> but takes an update lock on the row (UPDLOCK) until the current transaction ends,
    /// so a second rotation of the same token waits for the first to commit instead of deadlocking. Call inside an
    /// IUnitOfWork transaction.
    /// </summary>
    Task<RefreshToken?> GetByHashForUpdateAsync(byte[] tokenHash, CancellationToken cancellationToken);

    Task AddAsync(RefreshToken token, CancellationToken cancellationToken);

    /// <summary>Revokes every not-yet-revoked token of the family in one UPDATE. Returns the number revoked.</summary>
    Task<int> RevokeFamilyAsync(Guid familyId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>
    /// Like <see cref="RevokeFamilyAsync"/>, but only tokens of the family that belong to <paramref name="userId"/>, so a
    /// caller holding a family id can never end someone else's session. Returns the number revoked.
    /// </summary>
    Task<int> RevokeFamilyForUserAsync(Guid familyId, Guid userId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>Revokes every not-yet-revoked token of the user in one UPDATE. Returns the number revoked.</summary>
    Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>Revokes every not-yet-revoked token issued to the client application, in one UPDATE. Returns the number revoked.</summary>
    Task<int> RevokeAllForClientApplicationAsync(Guid clientApplicationId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes the live tokens of the user's families at the client application that STARTED at or after
    /// <paramref name="sinceUtc"/> (no token of the family is older), in one UPDATE. Replay fallback for an authorization
    /// code redeemed before its family id was recorded. Returns the number revoked.
    /// </summary>
    Task<int> RevokeFamiliesStartedSinceAsync(Guid userId, Guid clientApplicationId, DateTime sinceUtc, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>Revokes every not-yet-revoked token of every user holding the role, in one UPDATE. Returns the number revoked.</summary>
    Task<int> RevokeAllForRoleHoldersAsync(Guid roleId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>The user's tokens that are neither revoked nor expired at <paramref name="utcNow"/>, newest first.</summary>
    Task<IReadOnlyList<RefreshToken>> GetActiveByUserAsync(Guid userId, DateTime utcNow, CancellationToken cancellationToken);

    /// <summary>When the family started: the earliest CreatedUtc of its tokens, or null for an unknown family.
    /// The 30-day absolute session cap is computed from this, so any future purge of old refresh tokens must delete
    /// whole families only: deleting a family's oldest rows would move its start later and extend the session.
    /// </summary>
    Task<DateTime?> GetFamilyCreatedUtcAsync(Guid familyId, CancellationToken cancellationToken);

    /// <summary>
    /// The user's live sessions at <paramref name="utcNow"/> (families with a token that is neither revoked nor expired),
    /// one row per family, most recently used first, at most <paramref name="max"/>.
    /// </summary>
    Task<IReadOnlyList<IRefreshSessionSummary>> GetActiveSessionsAsync(Guid userId, DateTime utcNow, int max, CancellationToken cancellationToken);

    /// <summary>
    /// True when the family still has a token of <paramref name="userId"/> that is neither revoked nor expired at
    /// <paramref name="utcNow"/>, the user is active and, for an application's family, the application is active. One
    /// query (the access-token live-session check).
    /// </summary>
    Task<bool> IsSessionLiveAsync(Guid familyId, Guid userId, DateTime utcNow, CancellationToken cancellationToken);

    /// <summary>True when the family has at least one token of <paramref name="userId"/>, in any state.</summary>
    Task<bool> FamilyBelongsToUserAsync(Guid familyId, Guid userId, CancellationToken cancellationToken);
}

/// <summary>Single-use hashed tokens: <see cref="PasswordResetToken"/>, <see cref="EmailVerificationToken"/>, <see cref="MfaRecoveryCode"/>.</summary>
public interface IOneTimeTokenRepository<T>
    where T : class
{
    Task<T?> GetByHashAsync(byte[] hash, CancellationToken cancellationToken);

    Task AddAsync(T token, CancellationToken cancellationToken);

    /// <summary>
    /// Sets UsedUtc only if the token is still unused, in one conditional UPDATE. Returns false when it was already used
    /// (or does not exist), so two concurrent redemptions cannot both succeed. The same UPDATE erases the token's
    /// secret payload (EmailVerificationToken: PendingPasswordHash, PendingDisplayName); read it before calling this.
    /// </summary>
    Task<bool> TryMarkUsedAsync(Guid id, DateTime usedUtc, CancellationToken cancellationToken);

    /// <summary>Marks all of the user's unused tokens as used (erasing their payload), in one UPDATE. Returns the number changed.</summary>
    Task<int> InvalidateAllForUserAsync(Guid userId, DateTime usedUtc, CancellationToken cancellationToken);
}

public interface IClientApplicationRepository
{
    Task<ClientApplication?> GetByIdAsync(Guid id, CancellationToken cancellationToken);

    Task<ClientApplication?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken);

    Task<IReadOnlyList<ClientApplication>> GetActiveAsync(CancellationToken cancellationToken);

    /// <summary>Every application, active or not, ordered by client id.</summary>
    Task<IReadOnlyList<ClientApplication>> GetAllAsync(CancellationToken cancellationToken);

    /// <summary>True when at least one application is registered.</summary>
    Task<bool> AnyAsync(CancellationToken cancellationToken);

    /// <summary>True when another application (not <paramref name="exceptId"/>) already uses the audience (case-insensitive).</summary>
    Task<bool> IsAudienceInUseAsync(string audience, Guid? exceptId, CancellationToken cancellationToken);

    Task AddAsync(ClientApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Attaches a <b>detached</b> application (one not loaded in this scope) and marks every column modified.
    /// Only for detached entities: entities returned by this repository are already tracked, so just change them and
    /// call <see cref="Auth.DAL.IUnitOfWork.SaveChangesAsync"/>. Calling Update on a tracked entity is unnecessary,
    /// and calling it with a second instance of an already-tracked row throws.
    /// </summary>
    void Update(ClientApplication application);
}

public interface ISigningKeyRepository
{
    /// <summary>Keys to publish in the JWKS: status Active or Retiring.</summary>
    Task<IReadOnlyList<SigningKey>> GetPublishableAsync(CancellationToken cancellationToken);

    /// <summary>The Active key with the latest ActivatedUtc, or null.</summary>
    Task<SigningKey?> GetActiveAsync(CancellationToken cancellationToken);

    Task<SigningKey?> GetByKidAsync(string kid, CancellationToken cancellationToken);

    Task AddAsync(SigningKey key, CancellationToken cancellationToken);
}

public interface IAuditLogRepository
{
    Task AddAsync(AuditLog entry, CancellationToken cancellationToken);
}
