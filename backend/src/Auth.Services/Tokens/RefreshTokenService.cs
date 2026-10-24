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
        DateTime now = clock.UtcNow;

        try
        {
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
        catch (ConcurrencyConflictException)
        {
            // Another refresh of the same token committed first (RowVersion mismatch or deadlock victim). Our transaction
            // is rolled back; the winner's successor is the live token.
            return RotationResult.Concurrent;
        }
    }

    public Task<int> RevokeFamilyAsync(Guid familyId, string reason, CancellationToken cancellationToken) =>
        refreshTokens.RevokeFamilyAsync(familyId, CheckReason(reason), clock.UtcNow, cancellationToken);

    public Task<int> RevokeAllAsync(Guid userId, string reason, CancellationToken cancellationToken) =>
        refreshTokens.RevokeAllForUserAsync(userId, CheckReason(reason), clock.UtcNow, cancellationToken);

    /// <summary>A7: the token was rotated (not revoked for another reason) within the grace window, from the same user agent.</summary>
    private bool IsLosingSideOfARace(RefreshToken presented, RefreshContext context, DateTime now) =>
        presented.RevokedReason == RefreshTokenRevokedReason.Rotated
        && presented.ReplacedByTokenId is not null
        && now - presented.RevokedUtc!.Value <= options.ReuseGraceWindow
        && string.Equals(presented.UserAgent, context.UserAgent, StringComparison.Ordinal);

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
            IpAddress = Truncate(context.IpAddress, 45),
            UserAgent = Truncate(context.UserAgent, 512),
        };
        return (row, token.Value);
    }

    private static string CheckReason(string reason) =>
        RevokeReasons.Contains(reason) ? reason : throw new ArgumentException("Unknown revocation reason.", nameof(reason));

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    private static DateTime Min(DateTime a, DateTime b) => a <= b ? a : b;
}
