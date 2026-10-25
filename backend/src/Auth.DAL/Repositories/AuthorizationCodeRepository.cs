using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL.Repositories;

/// <summary>OAuth authorization codes (T19): stored hashed, redeemed at most once by a conditional UPDATE.</summary>
public interface IAuthorizationCodeRepository
{
    /// <summary>Stages a new code; saved by IUnitOfWork.SaveChangesAsync.</summary>
    Task AddAsync(AuthorizationCode code, CancellationToken cancellationToken);

    /// <summary>The code with this hash, untracked, in any state; null when unknown.</summary>
    Task<AuthorizationCode?> FindByHashAsync(byte[] codeHash, CancellationToken cancellationToken);

    /// <summary>
    /// Sets UsedUtc AND the refresh family the redemption will start, only if the code is still unused, in one
    /// conditional UPDATE. False when it was already used (or does not exist), so two concurrent redemptions cannot both
    /// win, and a replay always finds the family to revoke.
    /// </summary>
    Task<bool> TryRedeemAsync(Guid id, DateTime usedUtc, Guid familyId, CancellationToken cancellationToken);

    /// <summary>The family recorded for the code (fresh read, untracked); null when none was recorded.</summary>
    Task<Guid?> GetFamilyAsync(Guid id, CancellationToken cancellationToken);
}

internal sealed class AuthorizationCodeRepository(AuthDbContext context) : IAuthorizationCodeRepository
{
    public async Task AddAsync(AuthorizationCode code, CancellationToken cancellationToken) =>
        await context.AuthorizationCode.AddAsync(code, cancellationToken);

    public Task<AuthorizationCode?> FindByHashAsync(byte[] codeHash, CancellationToken cancellationToken) =>
        context.AuthorizationCode.AsNoTracking().FirstOrDefaultAsync(c => c.CodeHash == codeHash, cancellationToken);

    public async Task<bool> TryRedeemAsync(Guid id, DateTime usedUtc, Guid familyId, CancellationToken cancellationToken) =>
        await context.AuthorizationCode
            .Where(c => c.Id == id && c.UsedUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.UsedUtc, usedUtc).SetProperty(c => c.FamilyId, familyId), cancellationToken) == 1;

    public Task<Guid?> GetFamilyAsync(Guid id, CancellationToken cancellationToken) =>
        context.AuthorizationCode.AsNoTracking().Where(c => c.Id == id).Select(c => c.FamilyId).FirstOrDefaultAsync(cancellationToken);
}
