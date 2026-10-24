using Auth.Contracts.Responses;

namespace Auth.Services.Tokens;

/// <summary>Publishes the public signing keys. Signing and validation keys are used internally by the token service.</summary>
public interface ISigningKeyProvider
{
    /// <summary>The JWKS: every published key (upcoming, active and still-retiring), public parameters only.</summary>
    Task<JwksDocument> GetJwksAsync(CancellationToken cancellationToken);
}

/// <summary>Manages the key lifecycle. Run <see cref="RetireSupersededAsync"/> periodically (and at startup).</summary>
public interface ISigningKeyRotation
{
    /// <summary>
    /// Registers a key whose private part is already in the secret store under <paramref name="privateKeyReference"/>.
    /// It is published at once but signs only from <paramref name="activateAtUtc"/>, which must be at least
    /// token lifetime plus skew away, so clients have its public key before they meet a token signed with it.
    /// The very first key (nothing signing yet) may activate immediately.
    /// </summary>
    Task AddKeyAsync(string kid, string algorithm, string privateKeyReference, DateTime activateAtUtc, CancellationToken cancellationToken);

    /// <summary>
    /// Moves Active keys superseded by the current signing key to Retiring, published until the superseding activation
    /// plus token lifetime plus skew, and moves Retiring keys past that time to Retired. Returns the number of keys changed.
    /// </summary>
    Task<int> RetireSupersededAsync(CancellationToken cancellationToken);
}
