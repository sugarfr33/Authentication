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
    /// Before a new family is issued for <paramref name="clientApplicationId"/> (null: a browser session), revokes live
    /// families beyond MaxSessionsPerUser - 1, each audited as SessionRevoked with reason session_cap. The SAME client's
    /// families go first (least recently used first), then the least recently used of the others: one application
    /// cannot evict the user's other sessions while it still has its own (T19 recheck L-B). Returns the number ended.
    /// Two starts at the same moment can briefly leave one session over the cap; the next start trims it.
    /// </summary>
    /// <param name="userId">The user.</param>
    /// <param name="clientApplicationId">The application of the family about to start, or null for the browser.</param>
    /// <param name="audit">Who is asking.</param>
    /// <param name="stageAudit">True inside a caller's transaction: the audit rows are staged and saved by the family's
    /// own save, in the same transaction (no ClearChanges on a failed audit write there). False: written at once, best
    /// effort.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    Task<int> MakeRoomAsync(Guid userId, Guid? clientApplicationId, AuditContext audit, bool stageAudit, CancellationToken cancellationToken);
}

internal sealed class SessionCap(
    IRefreshTokenRepository refreshRows,
    IRefreshTokenService refreshTokens,
    IAuditService audits,
    ISessionLiveness liveness,
    RefreshTokenOptions options,
    IClock clock) : ISessionCap
{
    public async Task<int> MakeRoomAsync(Guid userId, Guid? clientApplicationId, AuditContext audit, bool stageAudit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        IReadOnlyList<IRefreshSessionSummary> live = await refreshRows.GetActiveSessionsAsync(userId, clock.UtcNow, options.MaxSessionsPerUser + 100, cancellationToken);
        int excess = live.Count - (options.MaxSessionsPerUser - 1);
        if (excess <= 0)
        {
            return 0;
        }

        // The list is most recently used first: reversed, it is least recently used first.
        IEnumerable<IRefreshSessionSummary> victims = live.Reverse()
            .OrderBy(s => s.ClientApplicationId == clientApplicationId ? 0 : 1)
            .Take(excess);
        int ended = 0;
        foreach (IRefreshSessionSummary victim in victims)
        {
            if (await refreshTokens.RevokeFamilyForUserAsync(victim.FamilyId, userId, RefreshTokenRevokedReason.Admin, cancellationToken) > 0)
            {
                ended++;
                liveness.Invalidate(victim.FamilyId);
                AuditEvent revoked = AuditEvents.SessionRevoked(userId, victim.FamilyId, "session_cap");
                if (stageAudit)
                {
                    await audits.StageAsync(revoked, audit, cancellationToken);
                }
                else
                {
                    await audits.TryWriteAsync(revoked, audit, cancellationToken);
                }
            }
        }

        return ended;
    }
}
