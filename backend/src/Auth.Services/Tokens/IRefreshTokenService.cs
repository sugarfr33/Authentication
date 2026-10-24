namespace Auth.Services.Tokens;

/// <summary>Refresh-token lifetimes and the race grace window (plan A7, A8).</summary>
public sealed class RefreshTokenOptions
{
    /// <summary>Each rotation extends the session by this much (sliding).</summary>
    public TimeSpan SlidingLifetime { get; init; } = TimeSpan.FromDays(14);

    /// <summary>A family (session) never outlives its first token by more than this.</summary>
    public TimeSpan AbsoluteLifetime { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// A token rotated less than this long ago, presented again with the same user agent, is treated as the losing side of
    /// a concurrent refresh, not as theft.
    /// </summary>
    public TimeSpan ReuseGraceWindow { get; init; } = TimeSpan.FromSeconds(10);

    internal RefreshTokenOptions Validated()
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(SlidingLifetime, TimeSpan.Zero, nameof(SlidingLifetime));
        ArgumentOutOfRangeException.ThrowIfLessThan(AbsoluteLifetime, SlidingLifetime, nameof(AbsoluteLifetime));
        ArgumentOutOfRangeException.ThrowIfLessThan(ReuseGraceWindow, TimeSpan.Zero, nameof(ReuseGraceWindow));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ReuseGraceWindow, TimeSpan.FromSeconds(30), nameof(ReuseGraceWindow));
        return this;
    }
}

/// <summary>Where a refresh came from; stored on every token row.</summary>
public sealed record RefreshContext(string IpAddress, string UserAgent);

/// <summary>A newly issued refresh token. <see cref="Token"/> is the only copy of the raw value: send it to the client, never store or log it.</summary>
public sealed record IssuedRefreshToken(string Token, Guid FamilyId, Guid UserId, Guid? ClientApplicationId, DateTime ExpiresUtc);

public enum RotationStatus
{
    /// <summary>Unknown, expired or unusable (inactive user or application). Deliberately does not say which.</summary>
    Invalid = 0,

    /// <summary>A new token was issued in the same family; the presented one is revoked as Rotated.</summary>
    Rotated,

    /// <summary>
    /// The presented token was rotated moments ago (within the grace window, same user agent): another request won the race.
    /// Nothing was revoked; the client should retry with the token the winner received.
    /// </summary>
    Concurrent,

    /// <summary>An already-rotated or revoked token was replayed. The whole family is revoked (Reuse); force a new login.</summary>
    ReuseDetected,
}

/// <summary>Who was affected by a detected reuse: what T17 writes to the audit log as TokenReuse.</summary>
public sealed record TokenReuseDetected(Guid UserId, Guid FamilyId, Guid? ClientApplicationId, string IpAddress, string UserAgent, int RevokedCount);

/// <summary>Outcome of <see cref="IRefreshTokenService.RotateAsync"/>.</summary>
public sealed record RotationResult(RotationStatus Status, IssuedRefreshToken? Token, TokenReuseDetected? Reuse)
{
    internal static readonly RotationResult Invalid = new(RotationStatus.Invalid, null, null);
    internal static readonly RotationResult Concurrent = new(RotationStatus.Concurrent, null, null);
}

/// <summary>Opaque, rotating refresh tokens with reuse detection. A session is one token family.</summary>
public interface IRefreshTokenService
{
    /// <summary>Starts a new family (session) for the user and returns its first token.</summary>
    Task<IssuedRefreshToken> IssueAsync(Guid userId, Guid? clientApplicationId, RefreshContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Exchanges a token for its successor in one RepeatableRead transaction with a RowVersion check, so of two
    /// simultaneous refreshes exactly one wins and the other gets <see cref="RotationStatus.Concurrent"/>.
    /// </summary>
    Task<RotationResult> RotateAsync(string rawToken, RefreshContext context, CancellationToken cancellationToken);

    /// <summary>Revokes every live token of one session (one set-based UPDATE). <paramref name="reason"/> is a RefreshTokenRevokedReason value.</summary>
    Task<int> RevokeFamilyAsync(Guid familyId, string reason, CancellationToken cancellationToken);

    /// <summary>Revokes every live token of the user, i.e. all sessions (one set-based UPDATE).</summary>
    Task<int> RevokeAllAsync(Guid userId, string reason, CancellationToken cancellationToken);
}
