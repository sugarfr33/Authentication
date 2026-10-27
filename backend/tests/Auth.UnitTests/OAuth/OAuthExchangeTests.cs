using System.Data;
using System.Security.Cryptography;
using System.Text;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Audit;
using Auth.Services.ClientApplications;
using Auth.Services.Common;
using Auth.Services.OAuth;
using Auth.Services.Security;
using Auth.Services.Tokens;

namespace Auth.UnitTests.OAuth;

/// <summary>
/// The exchange branches of OAuthService with a fake code store (no database): PKCE, the burn-first rule, the family
/// recorded with the burn and handed to StartAsync, and replay revocation (T19 arch review).
/// </summary>
public class OAuthExchangeTests
{
    private const string Verifier = "dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKQ";
    private const string RawCode = "the-raw-code";
    private const string RedirectUri = "https://spa.example.test/callback";

    private static readonly DateTime Now = new(2026, 10, 25, 12, 0, 0, DateTimeKind.Utc);

    private readonly FakeCodes codes = new();
    private readonly FakeSessions sessions = new();
    private readonly FakeAudit audits = new();
    private readonly FakeUnitOfWork unitOfWork = new();
    private readonly Stub<IRefreshTokenRepository> refreshRows;
    private readonly ClientApplication application = new() { Id = Guid.NewGuid(), ClientId = "spa", IsActive = true, RedirectUris = "[\"" + RedirectUri + "\"]" };
    private readonly OAuthService service;
    private readonly TokenGenerator generator = new();

    public OAuthExchangeTests()
    {
        (IClientApplicationRepository applications, Stub<IClientApplicationRepository> applicationStub) = Stubs.Create<IClientApplicationRepository>();
        applicationStub.Handlers[nameof(IClientApplicationRepository.GetByClientIdAsync)] =
            args => Task.FromResult<ClientApplication?>(string.Equals((string)args[0]!, application.ClientId, StringComparison.OrdinalIgnoreCase) ? application : null);
        (IRefreshTokenRepository refresh, refreshRows) = Stubs.Create<IRefreshTokenRepository>();
        refreshRows.Handlers[nameof(IRefreshTokenRepository.RevokeFamilyAsync)] = _ => Task.FromResult(1);

        service = new OAuthService(
            Stubs.Create<IClientApplicationOriginProvider>().Instance,
            applications,
            Stubs.Create<IUserRepository>().Instance,
            Stubs.Create<IRoleRepository>().Instance,
            codes,
            refresh,
            sessions,
            new PublicClientAuthenticator(),
            new FirstPartyAutoApproval(),
            generator,
            audits,
            unitOfWork,
            Stubs.Create<ISessionLiveness>().Instance,
            Stubs.Create<ISessionEndedPublisher>().Instance,
            new OAuthOptions(),
            new FixedClock());
        codes.Code = new AuthorizationCode
        {
            Id = Guid.NewGuid(),
            CodeHash = generator.Hash(RawCode),
            UserId = Guid.NewGuid(),
            ClientApplicationId = application.Id,
            RedirectUri = RedirectUri,
            CodeChallenge = Challenge(Verifier),
            CreatedUtc = Now.AddSeconds(-5),
            ExpiresUtc = Now.AddSeconds(55),
        };
    }

    [Fact]
    public async Task The_right_verifier_starts_the_session_recorded_with_the_burn_in_one_committed_transaction()
    {
        TokenGrantResult result = await ExchangeAsync(Verifier);

        Assert.True(result.IsSuccess);
        Assert.Equal(codes.RedeemedFamily, sessions.StartedFamily);
        Assert.NotEqual(Guid.Empty, sessions.StartedFamily);
        Assert.Equal((1, 1), (unitOfWork.Begun, unitOfWork.Committed));
        Assert.Contains(audits.Written, e => e.Type == AuditEventType.AuthorizationCodeRedeemed);
    }

    [Theory]
    [InlineData("dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKR")]
    [InlineData("DsBXq9E2fBCRJUhGT6UXeHBt8EVGWP5PUGmVXidcjCI")]
    [InlineData("dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMK")]
    [InlineData("dBjftJeZ4CVP-mJ92K9qO7JcNx7ap2dsPS-aaHoJMKQ\n")]
    [InlineData("dBjftJeZ4CVP+mJ92K9qO7JcNx7ap2dsPS/aaHoJMKQ")]
    public async Task Any_other_verifier_is_invalid_grant_burns_the_code_and_starts_nothing(string verifier)
    {
        TokenGrantResult result = await ExchangeAsync(verifier);

        Assert.Equal(OAuthErrorCodes.InvalidGrant, result.Error);
        Assert.NotNull(codes.RedeemedFamily);
        Assert.Equal(1, unitOfWork.Committed);
        Assert.Null(sessions.StartedFamily);
        Assert.Contains(audits.Written, e => e.Type == AuditEventType.AuthorizationCodeRejected && AuditDetail.Render(e)!.Contains("pkce_mismatch", StringComparison.Ordinal));
    }

    /// <summary>T19 recheck L-A: the redirect URI on the code must still be registered.</summary>
    [Fact]
    public async Task A_redirect_uri_no_longer_registered_is_refused()
    {
        application.RedirectUris = "[\"https://spa.example.test/other\"]";

        TokenGrantResult result = await ExchangeAsync(Verifier);

        Assert.Equal(OAuthErrorCodes.InvalidGrant, result.Error);
        Assert.Null(sessions.StartedFamily);
        Assert.Contains(audits.Written, e => e.Type == AuditEventType.AuthorizationCodeRejected && AuditDetail.Render(e)!.Contains("redirect_mismatch", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_replay_revokes_the_family_recorded_on_the_code_and_starts_nothing()
    {
        Guid family = Guid.NewGuid();
        codes.Code!.UsedUtc = Now.AddSeconds(-1);
        codes.Code.FamilyId = family;

        TokenGrantResult result = await ExchangeAsync(Verifier);

        Assert.Equal(OAuthErrorCodes.InvalidGrant, result.Error);
        Assert.Null(sessions.StartedFamily);
        Assert.Equal(0, unitOfWork.Committed);
        Assert.Contains(nameof(IRefreshTokenRepository.RevokeFamilyAsync), refreshRows.Calls);
        Assert.Contains(audits.Written, e => e.Type == AuditEventType.AuthorizationCodeRejected && AuditDetail.Render(e)!.Contains("replayed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_unknown_code_is_invalid_grant_without_an_audit_row()
    {
        codes.Code = null;

        TokenGrantResult result = await ExchangeAsync(Verifier);

        Assert.Equal(OAuthErrorCodes.InvalidGrant, result.Error);
        Assert.Empty(audits.Written);
        Assert.Equal(0, unitOfWork.Begun);
    }

    private static string Challenge(string verifier) => OAuthService.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private Task<TokenGrantResult> ExchangeAsync(string verifier) => service.ExchangeAsync(
        new TokenExchangeRequest("authorization_code", RawCode, RedirectUri, application.ClientId, verifier),
        new RefreshContext("203.0.113.1", "tests"),
        AuditContext.None,
        CancellationToken.None);

    private sealed class FixedClock : IClock
    {
        public DateTime UtcNow => Now;
    }

    private sealed class FakeCodes : IAuthorizationCodeRepository
    {
        public AuthorizationCode? Code { get; set; }

        public Guid? RedeemedFamily { get; private set; }

        public Task AddAsync(AuthorizationCode code, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<AuthorizationCode?> FindByHashAsync(byte[] codeHash, CancellationToken cancellationToken) =>
            Task.FromResult(Code is not null && Code.CodeHash.AsSpan().SequenceEqual(codeHash) ? Code : null);

        public Task<bool> TryRedeemAsync(Guid id, DateTime usedUtc, Guid familyId, CancellationToken cancellationToken)
        {
            if (Code is null || Code.Id != id || Code.UsedUtc is not null)
            {
                return Task.FromResult(false);
            }

            (Code.UsedUtc, Code.FamilyId, RedeemedFamily) = (usedUtc, familyId, familyId);
            return Task.FromResult(true);
        }

        public Task<Guid?> GetFamilyAsync(Guid id, CancellationToken cancellationToken) => Task.FromResult(Code?.FamilyId);
    }

    private sealed class FakeSessions : IClientSessionService
    {
        public Guid? StartedFamily { get; private set; }

        public Task<Result<SignedIn>> StartAsync(Guid userId, string clientId, Guid familyId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
        {
            StartedFamily = familyId;
            return Task.FromResult(Result.Success(new SignedIn(
                new AccessToken("jwt", Now.AddMinutes(15)),
                new IssuedRefreshToken("refresh", familyId, userId, null, Now.AddDays(14)),
                new UserProfileResponse(userId, "a@example.test", true, "A", false, [], []))));
        }

        public Task<Result<SignedIn>> RefreshAsync(string? refreshToken, string clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeAudit : IAuditService
    {
        public List<AuditEvent> Written { get; } = [];

        public Task StageAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken)
        {
            Written.Add(auditEvent);
            return Task.CompletedTask;
        }

        public Task WriteAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken) => StageAsync(auditEvent, context, cancellationToken);

        public async Task<bool> TryWriteAsync(AuditEvent auditEvent, AuditContext context, CancellationToken cancellationToken)
        {
            await StageAsync(auditEvent, context, cancellationToken);
            return true;
        }
    }

    private sealed class FakeUnitOfWork : IUnitOfWork
    {
        public int Begun { get; private set; }

        public int Committed { get; private set; }

        public Task<IUnitOfWorkTransaction> BeginTransactionAsync(IsolationLevel isolationLevel, CancellationToken cancellationToken)
        {
            Begun++;
            return Task.FromResult<IUnitOfWorkTransaction>(new Transaction(this));
        }

        public void ClearChanges()
        {
        }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken) => Task.FromResult(0);

        private sealed class Transaction(FakeUnitOfWork owner) : IUnitOfWorkTransaction
        {
            public Task CommitAsync(CancellationToken cancellationToken)
            {
                owner.Committed++;
                return Task.CompletedTask;
            }

            public Task RollbackAsync(CancellationToken cancellationToken) => Task.CompletedTask;

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
