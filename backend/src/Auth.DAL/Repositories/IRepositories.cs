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

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetByHashAsync(byte[] tokenHash, CancellationToken cancellationToken);

    Task AddAsync(RefreshToken token, CancellationToken cancellationToken);

    /// <summary>Revokes every not-yet-revoked token of the family in one UPDATE. Returns the number revoked.</summary>
    Task<int> RevokeFamilyAsync(Guid familyId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>Revokes every not-yet-revoked token of the user in one UPDATE. Returns the number revoked.</summary>
    Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTime revokedUtc, CancellationToken cancellationToken);

    /// <summary>The user's tokens that are neither revoked nor expired at <paramref name="utcNow"/>, newest first.</summary>
    Task<IReadOnlyList<RefreshToken>> GetActiveByUserAsync(Guid userId, DateTime utcNow, CancellationToken cancellationToken);
}

/// <summary>Single-use hashed tokens: <see cref="PasswordResetToken"/>, <see cref="EmailVerificationToken"/>, <see cref="MfaRecoveryCode"/>.</summary>
public interface IOneTimeTokenRepository<T>
    where T : class
{
    Task<T?> GetByHashAsync(byte[] hash, CancellationToken cancellationToken);

    Task AddAsync(T token, CancellationToken cancellationToken);

    /// <summary>
    /// Sets UsedUtc only if the token is still unused, in one conditional UPDATE. Returns false when it was already used
    /// (or does not exist), so two concurrent redemptions cannot both succeed.
    /// </summary>
    Task<bool> TryMarkUsedAsync(Guid id, DateTime usedUtc, CancellationToken cancellationToken);

    /// <summary>Marks all of the user's unused tokens as used, in one UPDATE. Returns the number changed.</summary>
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
