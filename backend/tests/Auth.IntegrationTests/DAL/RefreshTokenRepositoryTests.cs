using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

public class RefreshTokenRepositoryTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public async Task Token_is_found_by_hash()
    {
        User user = TestData.User();
        RefreshToken token = TestData.RefreshToken(user.Id);
        await SeedAsync(user, token);

        RefreshToken? found = await InScopeAsync<IRefreshTokenRepository, RefreshToken?>(r => r.GetByHashAsync([.. token.TokenHash], Ct));

        Assert.Equal(token.Id, found?.Id);
        Assert.Null(await InScopeAsync<IRefreshTokenRepository, RefreshToken?>(r => r.GetByHashAsync(TestData.Hash(), Ct)));
    }

    [Fact]
    public async Task RevokeFamily_revokes_only_the_unrevoked_tokens_of_that_family_in_one_statement()
    {
        User user = TestData.User();
        Guid family = Guid.NewGuid();
        RefreshToken active1 = TestData.RefreshToken(user.Id, family);
        RefreshToken active2 = TestData.RefreshToken(user.Id, family);
        RefreshToken alreadyRotated = TestData.RefreshToken(user.Id, family);
        alreadyRotated.RevokedUtc = TestData.Now.AddHours(-1);
        alreadyRotated.RevokedReason = RefreshTokenRevokedReason.Rotated;
        RefreshToken otherFamily = TestData.RefreshToken(user.Id);
        await SeedAsync(user, active1, active2, alreadyRotated, otherFamily);

        Database.Commands.Reset();
        int revoked = await InScopeAsync<IRefreshTokenRepository, int>(
            r => r.RevokeFamilyAsync(family, RefreshTokenRevokedReason.Reuse, TestData.Now, Ct));
        IReadOnlyList<string> sent = Database.Commands.Commands;

        Assert.Equal(2, revoked);
        string statement = Assert.Single(sent);
        Assert.StartsWith("UPDATE", statement.TrimStart(), StringComparison.OrdinalIgnoreCase);

        await AssertRevokedAsync(active1.Id, RefreshTokenRevokedReason.Reuse);
        await AssertRevokedAsync(active2.Id, RefreshTokenRevokedReason.Reuse);
        await AssertRevokedAsync(alreadyRotated.Id, RefreshTokenRevokedReason.Rotated);
        await AssertRevokedAsync(otherFamily.Id, null);
    }

    [Fact]
    public async Task RevokeAllForUser_revokes_every_unrevoked_token_of_that_user_only_in_one_statement()
    {
        User user = TestData.User();
        User otherUser = TestData.User();
        RefreshToken session1 = TestData.RefreshToken(user.Id);
        RefreshToken session2 = TestData.RefreshToken(user.Id);
        RefreshToken someoneElse = TestData.RefreshToken(otherUser.Id);
        await SeedAsync(user, otherUser, session1, session2, someoneElse);

        Database.Commands.Reset();
        int revoked = await InScopeAsync<IRefreshTokenRepository, int>(
            r => r.RevokeAllForUserAsync(user.Id, RefreshTokenRevokedReason.LogoutAll, TestData.Now, Ct));

        Assert.Equal(2, revoked);
        Assert.Single(Database.Commands.Commands);
        await AssertRevokedAsync(session1.Id, RefreshTokenRevokedReason.LogoutAll);
        await AssertRevokedAsync(session2.Id, RefreshTokenRevokedReason.LogoutAll);
        await AssertRevokedAsync(someoneElse.Id, null);
    }

    [Fact]
    public async Task Active_tokens_exclude_revoked_expired_and_other_users_newest_first()
    {
        User user = TestData.User();
        User otherUser = TestData.User();
        RefreshToken older = TestData.RefreshToken(user.Id, createdUtc: TestData.Now.AddHours(-2));
        RefreshToken newer = TestData.RefreshToken(user.Id, createdUtc: TestData.Now.AddHours(-1));
        RefreshToken expired = TestData.RefreshToken(user.Id, createdUtc: TestData.Now.AddDays(-20), expiresUtc: TestData.Now.AddSeconds(-1));
        RefreshToken revoked = TestData.RefreshToken(user.Id);
        revoked.RevokedUtc = TestData.Now;
        revoked.RevokedReason = RefreshTokenRevokedReason.Logout;
        await SeedAsync(user, otherUser, older, newer, expired, revoked, TestData.RefreshToken(otherUser.Id));

        IReadOnlyList<RefreshToken> active = await InScopeAsync<IRefreshTokenRepository, IReadOnlyList<RefreshToken>>(
            r => r.GetActiveByUserAsync(user.Id, TestData.Now, Ct));

        Assert.Equal([newer.Id, older.Id], active.Select(t => t.Id));
    }

    [Fact]
    public async Task Concurrent_rotation_of_the_same_token_raises_ConcurrencyConflictException()
    {
        User user = TestData.User();
        RefreshToken token = TestData.RefreshToken(user.Id);
        await SeedAsync(user, token);

        await using AsyncServiceScope first = Database.CreateScope();
        await using AsyncServiceScope second = Database.CreateScope();
        RefreshToken firstCopy = (await first.ServiceProvider.GetRequiredService<IRefreshTokenRepository>().GetByHashAsync(token.TokenHash, Ct))!;
        RefreshToken secondCopy = (await second.ServiceProvider.GetRequiredService<IRefreshTokenRepository>().GetByHashAsync(token.TokenHash, Ct))!;

        firstCopy.RevokedUtc = TestData.Now;
        firstCopy.RevokedReason = RefreshTokenRevokedReason.Rotated;
        await first.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);

        secondCopy.RevokedUtc = TestData.Now;
        secondCopy.RevokedReason = RefreshTokenRevokedReason.Rotated;
        await Assert.ThrowsAsync<ConcurrencyConflictException>(
            () => second.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct));
    }

    private async Task AssertRevokedAsync(Guid tokenId, string? expectedReason)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        RefreshToken token = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().RefreshToken.FindAsync([tokenId], Ct)
            ?? throw new InvalidOperationException("Token missing: " + tokenId);

        Assert.Equal(expectedReason, token.RevokedReason);
        Assert.Equal(expectedReason is null, token.RevokedUtc is null);
    }
}
