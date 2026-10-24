using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests.DAL;

public class ClientApplicationSigningKeyAuditRepositoryTests(SqlServerDatabaseFixture database) : RepositoryTestBase(database)
{
    [Fact]
    public async Task Client_application_is_found_by_id_and_client_id()
    {
        ClientApplication app = TestData.ClientApplication();
        await SeedAsync(app);

        Assert.Equal(app.Id, (await InScopeAsync<IClientApplicationRepository, ClientApplication?>(r => r.GetByClientIdAsync(app.ClientId, Ct)))?.Id);
        Assert.Equal(app.ClientId, (await InScopeAsync<IClientApplicationRepository, ClientApplication?>(r => r.GetByIdAsync(app.Id, Ct)))?.ClientId);
        Assert.Null(await InScopeAsync<IClientApplicationRepository, ClientApplication?>(r => r.GetByClientIdAsync("missing", Ct)));
    }

    [Fact]
    public async Task Active_applications_exclude_inactive_ones()
    {
        ClientApplication active = TestData.ClientApplication();
        ClientApplication inactive = TestData.ClientApplication(isActive: false);
        await SeedAsync(active, inactive);

        IReadOnlyList<Guid> ids = (await InScopeAsync<IClientApplicationRepository, IReadOnlyList<ClientApplication>>(r => r.GetActiveAsync(Ct)))
            .Select(a => a.Id).ToList();

        Assert.Contains(active.Id, ids);
        Assert.DoesNotContain(inactive.Id, ids);
    }

    [Fact]
    public async Task Added_application_with_explicit_RequirePkce_false_keeps_false()
    {
        ClientApplication app = TestData.ClientApplication();
        app.RequirePkce = false;
        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IClientApplicationRepository>().AddAsync(app, Ct);
            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
        }

        ClientApplication? reloaded = await InScopeAsync<IClientApplicationRepository, ClientApplication?>(r => r.GetByIdAsync(app.Id, Ct));
        Assert.False(reloaded?.RequirePkce);
    }

    [Fact]
    public async Task Publishable_keys_are_active_and_retiring_and_active_key_is_the_latest_activated()
    {
        // Far-future activation times so keys seeded by other runs or tests cannot be "newer".
        DateTime farFuture = DateTime.SpecifyKind(DateTime.MaxValue.AddYears(-1), DateTimeKind.Utc);
        SigningKey olderActive = TestData.SigningKey(SigningKeyStatus.Active, farFuture);
        SigningKey newerActive = TestData.SigningKey(SigningKeyStatus.Active, farFuture.AddDays(1));
        SigningKey retiring = TestData.SigningKey(SigningKeyStatus.Retiring, TestData.Now);
        SigningKey retired = TestData.SigningKey(SigningKeyStatus.Retired, TestData.Now);
        await SeedAsync(olderActive, newerActive, retiring, retired);

        IReadOnlyList<Guid> publishable = (await InScopeAsync<ISigningKeyRepository, IReadOnlyList<SigningKey>>(r => r.GetPublishableAsync(Ct)))
            .Select(k => k.Id).ToList();
        SigningKey? active = await InScopeAsync<ISigningKeyRepository, SigningKey?>(r => r.GetActiveAsync(Ct));
        SigningKey? byKid = await InScopeAsync<ISigningKeyRepository, SigningKey?>(r => r.GetByKidAsync(retired.Kid, Ct));

        Assert.Contains(olderActive.Id, publishable);
        Assert.Contains(newerActive.Id, publishable);
        Assert.Contains(retiring.Id, publishable);
        Assert.DoesNotContain(retired.Id, publishable);
        Assert.Equal(newerActive.Id, active?.Id);
        Assert.Equal(retired.Id, byKid?.Id);
    }

    [Fact]
    public async Task Audit_entry_is_saved_with_an_identity_id()
    {
        User user = TestData.User();
        await SeedAsync(user);
        AuditLog entry = TestData.AuditLog(user.Id);

        await using (AsyncServiceScope scope = Database.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IAuditLogRepository>().AddAsync(entry, Ct);
            await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(Ct);
        }

        Assert.True(entry.Id > 0);
        await using AsyncServiceScope check = Database.CreateScope();
        Assert.True(await check.ServiceProvider.GetRequiredService<AuthDbContext>().AuditLog.AnyAsync(a => a.Id == entry.Id && a.UserId == user.Id, Ct));
    }
}
