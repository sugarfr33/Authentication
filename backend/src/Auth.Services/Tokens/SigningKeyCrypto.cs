using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Auth.Contracts.Responses;
using Auth.Entities;

namespace Auth.Services.Tokens;

/// <summary>
/// Key loading and JWK conversion for the two supported algorithms: ES256 (P-256) and RS256 (RSA, at least 2048 bits).
/// Public JWKs are always built from <c>ExportParameters(false)</c>, so private parameters cannot leak into them.
/// Error messages name the key id only, never key material.
/// </summary>
internal static class SigningKeyCrypto
{
    public const int MinimumRsaKeySizeBits = 2048;

    /// <summary>Loads a private key from PEM text (PKCS#8, SEC1 "EC PRIVATE KEY" or PKCS#1 "RSA PRIVATE KEY").</summary>
    public static AsymmetricAlgorithm LoadPrivateKey(string kid, string algorithm, string pem)
    {
        switch (algorithm)
        {
            case SigningKeyAlgorithm.ES256:
                ECDsa ec = ECDsa.Create();
                try
                {
                    ec.ImportFromPem(pem);
                    ECParameters parameters = ec.ExportParameters(includePrivateParameters: false);
                    if (!IsP256(parameters.Curve))
                    {
                        throw new InvalidOperationException("Signing key '" + kid + "' is not a P-256 key, which ES256 requires.");
                    }

                    return ec;
                }
                catch (Exception ex) when (ex is ArgumentException or CryptographicException)
                {
                    ec.Dispose();
                    throw new InvalidOperationException("Signing key '" + kid + "' could not be loaded as an ES256 private key.");
                }
                catch
                {
                    ec.Dispose();
                    throw;
                }

            case SigningKeyAlgorithm.RS256:
                RSA rsa = RSA.Create();
                try
                {
                    rsa.ImportFromPem(pem);
                    if (rsa.KeySize < MinimumRsaKeySizeBits)
                    {
                        throw new InvalidOperationException("Signing key '" + kid + "' is shorter than " + MinimumRsaKeySizeBits + " bits.");
                    }

                    return rsa;
                }
                catch (Exception ex) when (ex is ArgumentException or CryptographicException)
                {
                    rsa.Dispose();
                    throw new InvalidOperationException("Signing key '" + kid + "' could not be loaded as an RS256 private key.");
                }
                catch
                {
                    rsa.Dispose();
                    throw;
                }

            default:
                throw new InvalidOperationException("Signing key '" + kid + "' has unsupported algorithm '" + algorithm + "'.");
        }
    }

    /// <summary>The public JWK of a key, from its public parameters only.</summary>
    public static JsonWebKeyDto ToPublicJwk(string kid, string algorithm, AsymmetricAlgorithm key) => key switch
    {
        ECDsa ec => ToEcJwk(kid, algorithm, ec.ExportParameters(includePrivateParameters: false)),
        RSA rsa => ToRsaJwk(kid, algorithm, rsa.ExportParameters(includePrivateParameters: false)),
        _ => throw new InvalidOperationException("Signing key '" + kid + "' has an unsupported key type."),
    };

    /// <summary>A public-only key object for signature validation, rebuilt from a stored JWK.</summary>
    public static AsymmetricAlgorithm FromPublicJwk(JsonWebKeyDto jwk)
    {
        switch (jwk.Kty)
        {
            case "EC" when jwk.Crv == "P-256" && jwk.X is not null && jwk.Y is not null:
                ECParameters ec = new()
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = Base64Url.DecodeFromChars(jwk.X), Y = Base64Url.DecodeFromChars(jwk.Y) },
                };
                return ECDsa.Create(ec);

            case "RSA" when jwk.N is not null && jwk.E is not null:
                RSA rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters { Modulus = Base64Url.DecodeFromChars(jwk.N), Exponent = Base64Url.DecodeFromChars(jwk.E) });
                return rsa;

            default:
                throw new InvalidOperationException("Stored public key '" + jwk.Kid + "' is not a valid EC P-256 or RSA JWK.");
        }
    }

    public static string Serialize(JsonWebKeyDto jwk) => JsonSerializer.Serialize(jwk);

    public static JsonWebKeyDto Deserialize(string kid, string json)
    {
        try
        {
            return JsonSerializer.Deserialize<JsonWebKeyDto>(json) ?? throw new JsonException();
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("Stored public key '" + kid + "' is not valid JWK JSON.");
        }
    }

    /// <summary>True when the private key matches the published public JWK (same public parameters).</summary>
    public static bool Matches(string kid, string algorithm, AsymmetricAlgorithm privateKey, JsonWebKeyDto published) =>
        ToPublicJwk(kid, algorithm, privateKey) == published with { Kid = kid, Alg = algorithm };

    private static JsonWebKeyDto ToEcJwk(string kid, string algorithm, ECParameters parameters) =>
        new("EC", "sig", kid, algorithm, "P-256", Base64Url.EncodeToString(parameters.Q.X), Base64Url.EncodeToString(parameters.Q.Y), null, null);

    private static JsonWebKeyDto ToRsaJwk(string kid, string algorithm, RSAParameters parameters) =>
        new("RSA", "sig", kid, algorithm, null, null, null, Base64Url.EncodeToString(parameters.Modulus), Base64Url.EncodeToString(parameters.Exponent));

    private static bool IsP256(ECCurve curve) =>
        curve.IsNamed && (curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value || curve.Oid.FriendlyName is "nistP256" or "ECDSA_P256");
}
