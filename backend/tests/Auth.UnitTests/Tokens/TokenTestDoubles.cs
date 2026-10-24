using System.Data;
using System.Security.Cryptography;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.UnitTests.Tokens;

internal sealed class FakeClock(DateTime start) : IClock
{
    public DateTime UtcNow { get; private set; } = start;

    public void Advance(TimeSpan by) => UtcNow += by;

    public void Set(DateTime utc) => UtcNow = utc;
}

internal sealed class InMemorySecretStore : ISecretStore
{
    private readonly Dictionary<string, string> secrets = new(StringComparer.Ordinal);

    public List<string> Requested { get; } = [];

    public void Set(string name, string value) => secrets[name] = value;

    public Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken)
    {
        Requested.Add(name);
        return Task.FromResult(secrets.TryGetValue(name, out string? value) ? value : null);
    }
}

/// <summary>In-memory SigningKey table with the same filters as the real repository.</summary>
internal sealed class FakeSigningKeyRepository : ISigningKeyRepository
{
    public List<SigningKey> Rows { get; } = [];

    public int Reads { get; private set; }

    public Task<IReadOnlyList<SigningKey>> GetPublishableAsync(CancellationToken cancellationToken)
    {
        Reads++;
        IReadOnlyList<SigningKey> publishable = Rows
            .Where(k => k.Status == SigningKeyStatus.Active || k.Status == SigningKeyStatus.Retiring)
            .OrderBy(k => k.Kid, StringComparer.Ordinal)
            .ToList();
        return Task.FromResult(publishable);
    }

    public Task<SigningKey?> GetActiveAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Rows.Where(k => k.Status == SigningKeyStatus.Active).OrderByDescending(k => k.ActivatedUtc).FirstOrDefault());

    public Task<SigningKey?> GetByKidAsync(string kid, CancellationToken cancellationToken) =>
        Task.FromResult(Rows.FirstOrDefault(k => k.Kid == kid));

    public Task AddAsync(SigningKey key, CancellationToken cancellationToken)
    {
        key.Id = Guid.NewGuid();
        Rows.Add(key);
        return Task.CompletedTask;
    }

    public SigningKey Get(string kid) => Rows.Single(k => k.Kid == kid);
}

internal sealed class FakeUnitOfWork : IUnitOfWork
{
    public int Saves { get; private set; }

    public Task<IUnitOfWorkTransaction> BeginTransactionAsync(IsolationLevel isolationLevel, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public int Clears { get; private set; }

    public void ClearChanges() => Clears++;

    public Task<int> SaveChangesAsync(CancellationToken cancellationToken)
    {
        Saves++;
        return Task.FromResult(1);
    }
}

/// <summary>Wires the real provider and rotation over the fakes.</summary>
internal sealed class KeyHarness : IDisposable
{
    public static readonly DateTime Start = new(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);

    private readonly ServiceProvider services;

    public KeyHarness(TokenOptions? options = null, DateTime? start = null)
    {
        Clock = new FakeClock(start ?? Start);
        Options = (options ?? new TokenOptions { Issuer = "https://auth.example.test" }).Validated();
        ServiceCollection collection = new();
        collection.AddSingleton<ISigningKeyRepository>(Repository);
        services = collection.BuildServiceProvider();
        Provider = new SigningKeyProvider(services.GetRequiredService<IServiceScopeFactory>(), Secrets, Clock, Options);
        Rotation = new SigningKeyRotation(Repository, UnitOfWork, Secrets, Clock, Options, Provider);
    }

    public FakeClock Clock { get; }

    public InMemorySecretStore Secrets { get; } = new();

    public FakeSigningKeyRepository Repository { get; } = new();

    public FakeUnitOfWork UnitOfWork { get; } = new();

    public TokenOptions Options { get; }

    public SigningKeyProvider Provider { get; }

    public SigningKeyRotation Rotation { get; }

    public static string NewEcPem()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportPkcs8PrivateKeyPem();
    }

    public static string NewRsaPem(int bits = 2048)
    {
        using RSA key = RSA.Create(bits);
        return key.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>Stores a fresh private key under "ref-{kid}" and registers it through the real rotation service.</summary>
    public async Task<string> AddKeyAsync(string kid, DateTime activateAtUtc, string algorithm = SigningKeyAlgorithm.ES256)
    {
        string pem = algorithm == SigningKeyAlgorithm.ES256 ? NewEcPem() : NewRsaPem();
        Secrets.Set("ref-" + kid, pem);
        await Rotation.AddKeyAsync(kid, algorithm, "ref-" + kid, activateAtUtc, CancellationToken.None);
        return pem;
    }

    public void Dispose()
    {
        Provider.Dispose();
        services.Dispose();
    }
}
