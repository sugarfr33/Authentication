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
    /// <paramref name="utcNow"/>, and the user is active. One query (the access-token live-session check).
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
