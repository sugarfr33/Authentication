using System.Data;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;

namespace Auth.Services.Tokens;

internal sealed class RefreshTokenService(
    IRefreshTokenRepository refreshTokens,
    IUserRepository users,
    IClientApplicationRepository applications,
    IUnitOfWork unitOfWork,
    ITokenGenerator generator,
    IClock clock,
    RefreshTokenOptions options) : IRefreshTokenService
{
    /// <summary>Longer input cannot be one of our tokens; skip hashing and the lookup.</summary>
    private const int MaxTokenLength = 256;

    /// <summary>Column sizes (nvarchar(45) and nvarchar(512)); incoming values are truncated to these before storing AND comparing.</summary>
    private const int MaxIpAddressLength = 45;
    private const int MaxUserAgentLength = 512;

    private static readonly HashSet<string> RevokeReasons =
    [
        RefreshTokenRevokedReason.Rotated, RefreshTokenRevokedReason.Reuse, RefreshTokenRevokedReason.Logout,
        RefreshTokenRevokedReason.LogoutAll, RefreshTokenRevokedReason.PasswordChange, RefreshTokenRevokedReason.Admin,
    ];

    public async Task<IssuedRefreshToken> IssueAsync(Guid userId, Guid? clientApplicationId, RefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        DateTime now = clock.UtcNow;
        Guid familyId = Guid.NewGuid();
        (RefreshToken row, string raw) = NewToken(userId, clientApplicationId, familyId, now, now + options.SlidingLifetime, context);

        await refreshTokens.AddAsync(row, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new IssuedRefreshToken(raw, familyId, userId, clientApplicationId, row.ExpiresUtc);
    }

    public async Task<RotationResult> RotateAsync(string rawToken, RefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rawToken);
        ArgumentNullException.ThrowIfNull(context);
        if (rawToken.Length is 0 or > MaxTokenLength)
        {
            return RotationResult.Invalid;
        }

        byte[] hash = generator.Hash(rawToken);

        try
        {
            return await RotateOnceAsync(hash, context, cancellationToken);
        }
        catch (ConcurrencyConflictException)
        {
            // Lost a race: a sibling rotation committed first, or our reuse revocation was a deadlock victim. Our
            // transaction is rolled back. Retry once with a clean change tracker: the retry sees the current state and
            // either reports Concurrent (sibling won, same user agent) or applies the reuse revocation.
            unitOfWork.ClearChanges();
        }

        try
        {
            return await RotateOnceAsync(hash, context, cancellationToken);
        }
        catch (ConcurrencyConflictException)
        {
            unitOfWork.ClearChanges();
            return RotationResult.Concurrent;
        }
    }

    /// <summary>One rotation attempt in its own RepeatableRead transaction. Throws ConcurrencyConflictException when it loses a race.</summary>
    private async Task<RotationResult> RotateOnceAsync(byte[] hash, RefreshContext context, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);

        RefreshToken? presented = await refreshTokens.GetByHashForUpdateAsync(hash, cancellationToken);
        if (presented is null || presented.ExpiresUtc <= now)
        {
            return RotationResult.Invalid;
        }

        if (presented.RevokedUtc is not null)
        {
            if (IsLosingSideOfARace(presented, context, now))
            {
                return RotationResult.Concurrent;
            }

            int revoked = await refreshTokens.RevokeFamilyAsync(presented.FamilyId, RefreshTokenRevokedReason.Reuse, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new RotationResult(
                RotationStatus.ReuseDetected,
                null,
                new TokenReuseDetected(presented.UserId, presented.FamilyId, presented.ClientApplicationId, context.IpAddress, context.UserAgent, revoked));
        }

        if (!await CanRefreshAsync(presented, cancellationToken))
        {
            return RotationResult.Invalid;
        }

        DateTime familyStart = await refreshTokens.GetFamilyCreatedUtcAsync(presented.FamilyId, cancellationToken) ?? presented.CreatedUtc;
        DateTime expires = Min(now + options.SlidingLifetime, familyStart + options.AbsoluteLifetime);
        if (expires <= now)
        {
            return RotationResult.Invalid;
        }

        (RefreshToken successor, string raw) = NewToken(presented.UserId, presented.ClientApplicationId, presented.FamilyId, now, expires, context);
        await refreshTokens.AddAsync(successor, cancellationToken);

        presented.RevokedUtc = now;
        presented.RevokedReason = RefreshTokenRevokedReason.Rotated;
        // AddAsync has assigned successor.Id (EF client-side sequential GUID), so it can be referenced here.
        presented.ReplacedByTokenId = successor.Id;

        await unitOfWork.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new RotationResult(
            RotationStatus.Rotated,
            new IssuedRefreshToken(raw, presented.FamilyId, presented.UserId, presented.ClientApplicationId, expires),
            null);
    }

    public Task<int> RevokeFamilyAsync(Guid familyId, string reason, CancellationToken cancellationToken) =>
        refreshTokens.RevokeFamilyAsync(familyId, CheckReason(reason), clock.UtcNow, cancellationToken);

    public Task<int> RevokeFamilyForUserAsync(Guid familyId, Guid userId, string reason, CancellationToken cancellationToken) =>
        refreshTokens.RevokeFamilyForUserAsync(familyId, userId, CheckReason(reason), clock.UtcNow, cancellationToken);

    public async Task<RefreshSession?> FindSessionAsync(string? rawToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(rawToken) || rawToken.Length > MaxTokenLength)
        {
            return null;
        }

        RefreshToken? row = await refreshTokens.GetByHashAsync(generator.Hash(rawToken), cancellationToken);
        return row is null ? null : new RefreshSession(row.UserId, row.FamilyId);
    }

    public Task<int> RevokeAllAsync(Guid userId, string reason, CancellationToken cancellationToken) =>
        refreshTokens.RevokeAllForUserAsync(userId, CheckReason(reason), clock.UtcNow, cancellationToken);

    /// <summary>A7: the token was rotated (not revoked for another reason) within the grace window, from the same user agent.</summary>
    private bool IsLosingSideOfARace(RefreshToken presented, RefreshContext context, DateTime now) =>
        presented.RevokedReason == RefreshTokenRevokedReason.Rotated
        && presented.ReplacedByTokenId is not null
        && now - presented.RevokedUtc!.Value <= options.ReuseGraceWindow
        && string.Equals(presented.UserAgent, Truncate(context.UserAgent, MaxUserAgentLength), StringComparison.Ordinal);

    private async Task<bool> CanRefreshAsync(RefreshToken presented, CancellationToken cancellationToken)
    {
        User? user = await users.GetByIdAsync(presented.UserId, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return false;
        }

        if (presented.ClientApplicationId is null)
        {
            return true;
        }

        ClientApplication? application = await applications.GetByIdAsync(presented.ClientApplicationId.Value, cancellationToken);
        return application is not null && application.IsActive;
    }

    private (RefreshToken Row, string Raw) NewToken(Guid userId, Guid? clientApplicationId, Guid familyId, DateTime now, DateTime expires, RefreshContext context)
    {
        GeneratedToken token = generator.Generate();
        RefreshToken row = new()
        {
            UserId = userId,
            ClientApplicationId = clientApplicationId,
            FamilyId = familyId,
            TokenHash = token.Hash,
            CreatedUtc = now,
            ExpiresUtc = expires,
            IpAddress = Truncate(context.IpAddress, MaxIpAddressLength),
            UserAgent = Truncate(context.UserAgent, MaxUserAgentLength),
        };
        return (row, token.Value);
    }

    private static string CheckReason(string reason) =>
        RevokeReasons.Contains(reason) ? reason : throw new ArgumentException("Unknown revocation reason.", nameof(reason));

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    private static DateTime Min(DateTime a, DateTime b) => a <= b ? a : b;
}
