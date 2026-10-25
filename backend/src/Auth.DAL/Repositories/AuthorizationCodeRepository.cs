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
    /// Sets UsedUtc only if the code is still unused, in one conditional UPDATE. False when it was already used (or does
    /// not exist), so two concurrent redemptions cannot both win.
    /// </summary>
    Task<bool> TryMarkUsedAsync(Guid id, DateTime usedUtc, CancellationToken cancellationToken);

    /// <summary>Records the refresh family started from the code (for replay revocation). One UPDATE.</summary>
    Task<int> SetFamilyAsync(Guid id, Guid familyId, CancellationToken cancellationToken);
}

internal sealed class AuthorizationCodeRepository(AuthDbContext context) : IAuthorizationCodeRepository
{
    public async Task AddAsync(AuthorizationCode code, CancellationToken cancellationToken) =>
        await context.AuthorizationCode.AddAsync(code, cancellationToken);

    public Task<AuthorizationCode?> FindByHashAsync(byte[] codeHash, CancellationToken cancellationToken) =>
        context.AuthorizationCode.AsNoTracking().FirstOrDefaultAsync(c => c.CodeHash == codeHash, cancellationToken);

    public async Task<bool> TryMarkUsedAsync(Guid id, DateTime usedUtc, CancellationToken cancellationToken) =>
        await context.AuthorizationCode
            .Where(c => c.Id == id && c.UsedUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.UsedUtc, usedUtc), cancellationToken) == 1;

    public Task<int> SetFamilyAsync(Guid id, Guid familyId, CancellationToken cancellationToken) =>
        context.AuthorizationCode
            .Where(c => c.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.FamilyId, familyId), cancellationToken);
}
