using System.Data;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

/// <summary>Changes staged through several repositories commit or roll back together.</summary>
public class UnitOfWorkTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public async Task Committed_transaction_persists_changes_from_every_repository()
    {
        Work work = NewWork();

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            IUnitOfWork unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
            await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, Ct);
            await StageAsync(scope, work);
            await unitOfWork.SaveChangesAsync(Ct);
            await transaction.CommitAsync(Ct);
        }

        Assert.Equal((true, true, true), await ExistsAsync(work));
    }

    [Fact]
    public async Task Rolled_back_transaction_persists_nothing_even_after_SaveChanges()
    {
        Work work = NewWork();

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            IUnitOfWork unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
            await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, Ct);
            await StageAsync(scope, work);
            await unitOfWork.SaveChangesAsync(Ct);
            await transaction.RollbackAsync(Ct);
        }

        Assert.Equal((false, false, false), await ExistsAsync(work));
    }

    [Fact]
    public async Task Disposing_an_uncommitted_transaction_rolls_back()
    {
        Work work = NewWork();

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            IUnitOfWork unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
            await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, Ct))
            {
                await StageAsync(scope, work);
                await unitOfWork.SaveChangesAsync(Ct);
            }
        }

        Assert.Equal((false, false, false), await ExistsAsync(work));
    }

    [Fact]
    public async Task Set_based_revoke_inside_a_rolled_back_transaction_is_undone()
    {
        User user = TestData.User();
        RefreshToken token = TestData.RefreshToken(user.Id);
        await SeedAsync(user, token);

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            await using IUnitOfWorkTransaction transaction = await scope.ServiceProvider.GetRequiredService<IUnitOfWork>()
                .BeginTransactionAsync(IsolationLevel.RepeatableRead, Ct);
            int revoked = await scope.ServiceProvider.GetRequiredService<IRefreshTokenRepository>()
                .RevokeFamilyAsync(token.FamilyId, RefreshTokenRevokedReason.Reuse, TestData.Now, Ct);
            Assert.Equal(1, revoked);
            await transaction.RollbackAsync(Ct);
        }

        RefreshToken? reloaded = await InScopeAsync<IRefreshTokenRepository, RefreshToken?>(r => r.GetByHashAsync(token.TokenHash, Ct));
        Assert.Null(reloaded?.RevokedUtc);
    }

    [Fact]
    public async Task SaveChanges_is_atomic_when_one_row_fails()
    {
        User existing = TestData.User();
        await SeedAsync(existing);
        Work work = NewWork();
        User clash = TestData.User();
        clash.NormalizedEmail = existing.NormalizedEmail;

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            await StageAsync(scope, work);
            await scope.ServiceProvider.GetRequiredService<IUserRepository>().AddAsync(clash, Ct);
            await Assert.ThrowsAsync<UniqueConstraintViolationException>(
                () => scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct));
        }

        Assert.Equal((false, false, false), await ExistsAsync(work));
    }

    /// <summary>
    /// Two RepeatableRead transactions read the same row and then both update it: SQL Server kills one as deadlock
    /// victim (1205). EF wraps that in a "transient failure" InvalidOperationException; the unit of work must still
    /// surface it as ConcurrencyConflictException, and exactly one update survives.
    /// </summary>
    [Fact]
    public async Task Deadlock_victim_is_reported_as_ConcurrencyConflictException()
    {
        User user = TestData.User();
        await SeedAsync(user);
        using Barrier bothRead = new(2);

        Task<Exception?>[] writers = Enumerable.Range(1, 2).Select(n => Task.Run(async () =>
        {
            await using AsyncServiceScope scope = Database.CreateScope();
            IUnitOfWork unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
            try
            {
                await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.RepeatableRead, Ct);
                User copy = (await scope.ServiceProvider.GetRequiredService<IUserRepository>().GetByIdAsync(user.Id, Ct))!;
                bothRead.SignalAndWait(TimeSpan.FromSeconds(30));
                copy.FailedLoginCount = n;
                await unitOfWork.SaveChangesAsync(Ct);
                await transaction.CommitAsync(Ct);
                return null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        })).ToArray();

        Exception?[] outcomes = await Task.WhenAll(writers);

        Assert.Single(outcomes, e => e is null);
        Assert.IsType<ConcurrencyConflictException>(Assert.Single(outcomes, e => e is not null));
    }

    private static Work NewWork()
    {
        User user = TestData.User();
        return new Work(user, TestData.RefreshToken(user.Id), "corr-" + Guid.NewGuid().ToString("N"));
    }

    /// <summary>Stages a user, a refresh token and an audit entry through three different repositories.</summary>
    private static async Task StageAsync(AsyncServiceScope scope, Work work)
    {
        await scope.ServiceProvider.GetRequiredService<IUserRepository>().AddAsync(work.User, Ct);
        await scope.ServiceProvider.GetRequiredService<IRefreshTokenRepository>().AddAsync(work.Token, Ct);
        AuditLog audit = TestData.AuditLog(work.User.Id);
        audit.CorrelationId = work.CorrelationId;
        await scope.ServiceProvider.GetRequiredService<IAuditLogRepository>().AddAsync(audit, Ct);
    }

    private async Task<(bool User, bool Token, bool Audit)> ExistsAsync(Work work)
    {
        await using AsyncServiceScope scope = Database.CreateScope();
        AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        return (
            await context.User.AnyAsync(u => u.Id == work.User.Id, Ct),
            await context.RefreshToken.AnyAsync(t => t.Id == work.Token.Id, Ct),
            await context.AuditLog.AnyAsync(a => a.CorrelationId == work.CorrelationId, Ct));
    }

    private sealed record Work(User User, RefreshToken Token, string CorrelationId);
}
