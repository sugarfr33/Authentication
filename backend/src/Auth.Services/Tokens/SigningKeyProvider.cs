using System.Collections.Concurrent;
using System.Security.Cryptography;
using Auth.Contracts.Responses;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Services.Tokens;

/// <summary>A key that may sign right now. The private key comes from the secret store, never from the database.</summary>
internal sealed record ActiveSigningKey(string Kid, string Algorithm, AsymmetricAlgorithm PrivateKey);

/// <summary>A published key, as a public-only key object, for validating signatures.</summary>
internal sealed record ValidationKey(string Kid, string Algorithm, AsymmetricAlgorithm PublicKey);

/// <summary>
/// Singleton view of the signing keys. A snapshot of the publishable rows is cached for
/// <see cref="TokenOptions.KeyCacheDuration"/>; the schedule is evaluated against the clock on every call, so a key
/// activates or drops out exactly on time even within one snapshot. Loaded key objects are cached by kid for the
/// provider's lifetime (rotation is rare), so an in-flight signature never sees a disposed key.
/// </summary>
internal sealed class SigningKeyProvider(
    IServiceScopeFactory scopeFactory,
    ISecretStore secretStore,
    IClock clock,
    TokenOptions options) : ISigningKeyProvider, IDisposable
{
    private readonly SemaphoreSlim refreshLock = new(1, 1);
    private readonly ConcurrentDictionary<string, AsymmetricAlgorithm> privateKeys = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AsymmetricAlgorithm> publicKeys = new(StringComparer.Ordinal);
    private Snapshot? snapshot;

    public async Task<JwksDocument> GetJwksAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<SigningKey> published = SigningKeySchedule.Published(await GetRowsAsync(cancellationToken), clock.UtcNow);

        // Rebuilt from the parsed public parameters, so a stored JWK carrying extra (private) members cannot pass through.
        List<JsonWebKeyDto> keys = published
            .Select(k => SigningKeyCrypto.ToPublicJwk(k.Kid, k.Algorithm, PublicKey(k)))
            .ToList();

        return new JwksDocument(keys);
    }

    public async Task<ActiveSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
    {
        SigningKey key = SigningKeySchedule.CurrentSigningKey(await GetRowsAsync(cancellationToken), clock.UtcNow)
            ?? throw new InvalidOperationException("No signing key is active.");

        if (!privateKeys.TryGetValue(key.Kid, out AsymmetricAlgorithm? privateKey))
        {
            privateKey = await LoadPrivateKeyAsync(key, cancellationToken);
            privateKey = privateKeys.GetOrAdd(key.Kid, privateKey);
        }

        return new ActiveSigningKey(key.Kid, key.Algorithm, privateKey);
    }

    public async Task<IReadOnlyList<ValidationKey>> GetValidationKeysAsync(CancellationToken cancellationToken) =>
        SigningKeySchedule.Published(await GetRowsAsync(cancellationToken), clock.UtcNow)
            .Select(k => new ValidationKey(k.Kid, k.Algorithm, PublicKey(k)))
            .ToList();

    /// <summary>Forces the next call to re-read the database (after rotation changes).</summary>
    public void Invalidate() => snapshot = null;

    public void Dispose()
    {
        foreach (AsymmetricAlgorithm key in privateKeys.Values.Concat(publicKeys.Values))
        {
            key.Dispose();
        }

        refreshLock.Dispose();
    }

    private async Task<IReadOnlyList<SigningKey>> GetRowsAsync(CancellationToken cancellationToken)
    {
        Snapshot? current = snapshot;
        if (current is not null && clock.UtcNow < current.LoadedUtc + options.KeyCacheDuration)
        {
            return current.Rows;
        }

        await refreshLock.WaitAsync(cancellationToken);
        try
        {
            current = snapshot;
            if (current is not null && clock.UtcNow < current.LoadedUtc + options.KeyCacheDuration)
            {
                return current.Rows;
            }

            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            IReadOnlyList<SigningKey> rows = await scope.ServiceProvider.GetRequiredService<ISigningKeyRepository>()
                .GetPublishableAsync(cancellationToken);

            snapshot = new Snapshot(clock.UtcNow, rows.Select(Copy).ToList());
            return snapshot.Rows;
        }
        finally
        {
            refreshLock.Release();
        }
    }

    private AsymmetricAlgorithm PublicKey(SigningKey key) =>
        publicKeys.GetOrAdd(key.Kid, _ => SigningKeyCrypto.FromPublicJwk(SigningKeyCrypto.Deserialize(key.Kid, key.PublicKeyJwk)));

    private async Task<AsymmetricAlgorithm> LoadPrivateKeyAsync(SigningKey key, CancellationToken cancellationToken)
    {
        string pem = await secretStore.GetSecretAsync(key.PrivateKeyReference, cancellationToken)
            ?? throw new InvalidOperationException("The private key of signing key '" + key.Kid + "' was not found in the secret store.");

        AsymmetricAlgorithm privateKey = SigningKeyCrypto.LoadPrivateKey(key.Kid, key.Algorithm, pem);
        JsonWebKeyDto published = SigningKeyCrypto.Deserialize(key.Kid, key.PublicKeyJwk);
        if (!SigningKeyCrypto.Matches(key.Kid, key.Algorithm, privateKey, published))
        {
            privateKey.Dispose();
            throw new InvalidOperationException("The private key of signing key '" + key.Kid + "' does not match its published public key.");
        }

        return privateKey;
    }

    /// <summary>Detached copy, so the cache never holds a tracked entity from a disposed scope.</summary>
    private static SigningKey Copy(SigningKey key) => new()
    {
        Id = key.Id,
        Kid = key.Kid,
        Algorithm = key.Algorithm,
        PublicKeyJwk = key.PublicKeyJwk,
        PrivateKeyReference = key.PrivateKeyReference,
        Status = key.Status,
        CreatedUtc = key.CreatedUtc,
        ActivatedUtc = key.ActivatedUtc,
        RetireAfterUtc = key.RetireAfterUtc,
    };

    private sealed record Snapshot(DateTime LoadedUtc, IReadOnlyList<SigningKey> Rows);
}
