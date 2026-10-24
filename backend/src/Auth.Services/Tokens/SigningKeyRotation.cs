using System.Security.Cryptography;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Common;

namespace Auth.Services.Tokens;

internal sealed class SigningKeyRotation(
    ISigningKeyRepository repository,
    IUnitOfWork unitOfWork,
    ISecretStore secretStore,
    IClock clock,
    TokenOptions options,
    SigningKeyProvider provider) : ISigningKeyRotation
{
    private const int MaxKidLength = 64;
    private const int MaxReferenceLength = 256;

    public async Task AddKeyAsync(string kid, string algorithm, string privateKeyReference, DateTime activateAtUtc, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyReference);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(kid.Length, MaxKidLength, nameof(kid));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(privateKeyReference.Length, MaxReferenceLength, nameof(privateKeyReference));
        if (algorithm is not (SigningKeyAlgorithm.ES256 or SigningKeyAlgorithm.RS256))
        {
            throw new ArgumentException("Algorithm must be ES256 or RS256.", nameof(algorithm));
        }

        if (await repository.GetByKidAsync(kid, cancellationToken) is not null)
        {
            throw new InvalidOperationException("A signing key with kid '" + kid + "' already exists.");
        }

        DateTime now = clock.UtcNow;
        IReadOnlyList<SigningKey> publishable = await repository.GetPublishableAsync(cancellationToken);
        bool bootstrap = SigningKeySchedule.CurrentSigningKey(publishable, now) is null;
        if (bootstrap && activateAtUtc < now)
        {
            // Nothing signs yet, so there is nothing to overlap with: the first key may start now (an earlier time means now).
            activateAtUtc = now;
        }

        if (!bootstrap && activateAtUtc < now + options.KeyOverlap)
        {
            throw new ArgumentOutOfRangeException(
                nameof(activateAtUtc),
                "A new key must be published at least the token lifetime plus clock skew before it signs.");
        }

        string pem = await secretStore.GetSecretAsync(privateKeyReference, cancellationToken)
            ?? throw new InvalidOperationException("The private key of signing key '" + kid + "' was not found in the secret store.");

        JsonWebKeyDto publicJwk;
        using (AsymmetricAlgorithm privateKey = SigningKeyCrypto.LoadPrivateKey(kid, algorithm, pem))
        {
            publicJwk = SigningKeyCrypto.ToPublicJwk(kid, algorithm, privateKey);
        }

        await repository.AddAsync(
            new SigningKey
            {
                Kid = kid,
                Algorithm = algorithm,
                PublicKeyJwk = SigningKeyCrypto.Serialize(publicJwk),
                PrivateKeyReference = privateKeyReference,
                Status = SigningKeyStatus.Active,
                CreatedUtc = now,
                ActivatedUtc = activateAtUtc,
            },
            cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        provider.Invalidate();
    }

    public async Task<int> RetireSupersededAsync(CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        IReadOnlyList<SigningKey> keys = await repository.GetPublishableAsync(cancellationToken);
        SigningKey? current = SigningKeySchedule.CurrentSigningKey(keys, now);
        HashSet<SigningKey> changed = [];

        if (current is not null)
        {
            // Tokens signed by a superseded key were issued before current.ActivatedUtc, so they are all expired
            // (allowing for skew) by that instant plus the overlap.
            DateTime retireAfter = current.ActivatedUtc!.Value + options.KeyOverlap;
            foreach (SigningKey superseded in keys.Where(k =>
                k != current && k.Status == SigningKeyStatus.Active && k.ActivatedUtc is not null && k.ActivatedUtc <= current.ActivatedUtc))
            {
                superseded.Status = SigningKeyStatus.Retiring;
                superseded.RetireAfterUtc = retireAfter;
                changed.Add(superseded);
            }
        }

        foreach (SigningKey expired in keys.Where(k => k.Status == SigningKeyStatus.Retiring && k.RetireAfterUtc is not null && k.RetireAfterUtc <= now))
        {
            expired.Status = SigningKeyStatus.Retired;
            changed.Add(expired);
        }

        if (changed.Count > 0)
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
            provider.Invalidate();
        }

        return changed.Count;
    }
}
