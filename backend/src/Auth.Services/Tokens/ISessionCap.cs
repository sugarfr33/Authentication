using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Security;

namespace Auth.Services.Tokens;

/// <summary>
/// The per-user session cap (RefreshTokens:MaxSessionsPerUser), counted across ALL of the user's families: browser
/// sessions and client-application sessions alike. Every path that starts a family calls it first.
/// </summary>
internal interface ISessionCap
{
    /// <summary>
    /// Before a new family is issued, revokes the least recently used live families beyond MaxSessionsPerUser - 1, each
    /// audited as SessionRevoked with reason session_cap. Returns the number of families ended. Two starts at the same
    /// moment can briefly leave one session over the cap; the next start trims it.
    /// </summary>
    Task<int> MakeRoomAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken);
}

internal sealed class SessionCap(
    IRefreshTokenRepository refreshRows,
    IRefreshTokenService refreshTokens,
    IAuditService audits,
    ISessionLiveness liveness,
    RefreshTokenOptions options,
    IClock clock) : ISessionCap
{
    public async Task<int> MakeRoomAsync(Guid userId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        int keep = options.MaxSessionsPerUser - 1;
        IReadOnlyList<IRefreshSessionSummary> live = await refreshRows.GetActiveSessionsAsync(userId, clock.UtcNow, options.MaxSessionsPerUser + 100, cancellationToken);
        int ended = 0;
        foreach (IRefreshSessionSummary oldest in live.Skip(keep))
        {
            if (await refreshTokens.RevokeFamilyForUserAsync(oldest.FamilyId, userId, RefreshTokenRevokedReason.Admin, cancellationToken) > 0)
            {
                ended++;
                liveness.Invalidate(oldest.FamilyId);
                await audits.TryWriteAsync(AuditEvents.SessionRevoked(userId, oldest.FamilyId, "session_cap"), audit, cancellationToken);
            }
        }

        return ended;
    }
}
