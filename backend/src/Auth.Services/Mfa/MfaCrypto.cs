using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Auth.Services.Common;

namespace Auth.Services.Mfa;

/// <summary>A decrypted TOTP secret and the last time step accepted for it (replay protection).</summary>
internal sealed record MfaSecret(byte[] Secret, long LastUsedStep);

/// <summary>
/// The MFA keys (docs/mfa-totp.md section 2): AES-256-GCM protection of the TOTP secret blob, the HMAC key of login
/// challenges (HKDF from the active key) and the recovery-code pepper. Keys are read once through ISecretStore.
/// </summary>
internal interface IMfaCrypto
{
    /// <summary>Loads and checks every configured key; throws when one is missing or not 32 bytes (startup check).</summary>
    Task ValidateKeysAsync(CancellationToken cancellationToken);

    Task<byte[]> ProtectAsync(Guid userId, MfaSecret secret, CancellationToken cancellationToken);

    /// <summary>The secret, or null when the blob is malformed, for another user, or under an unknown key.</summary>
    Task<MfaSecret?> UnprotectAsync(Guid userId, byte[]? blob, CancellationToken cancellationToken);

    /// <summary>HMAC-SHA256 of a normalized recovery code under the pepper (32 bytes, fits MfaRecoveryCode.CodeHash).</summary>
    Task<byte[]> RecoveryHashAsync(string normalizedCode, CancellationToken cancellationToken);

    /// <summary>The HMAC key for login challenges, derived from the active encryption key.</summary>
    Task<byte[]> ChallengeKeyAsync(CancellationToken cancellationToken);
}

internal sealed class MfaCrypto(ISecretStore secrets, MfaOptions options) : IMfaCrypto, IDisposable
{
    private const byte FormatVersion = 1;
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int SecretBytes = 20;
    private const int PlainBytes = SecretBytes + 8;

    private readonly SemaphoreSlim loadLock = new(1, 1);
    private Keys? keys;

    public async Task ValidateKeysAsync(CancellationToken cancellationToken) => await LoadAsync(cancellationToken);

    public async Task<byte[]> ProtectAsync(Guid userId, MfaSecret secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Secret.Length != SecretBytes)
        {
            throw new ArgumentException("A TOTP secret is 20 bytes.", nameof(secret));
        }

        Keys loaded = await LoadAsync(cancellationToken);
        byte[] keyId = Encoding.ASCII.GetBytes(options.ActiveKeyId);
        byte[] plain = new byte[PlainBytes];
        secret.Secret.CopyTo(plain, 0);
        BinaryPrimitives.WriteInt64BigEndian(plain.AsSpan(SecretBytes), secret.LastUsedStep);

        byte[] blob = new byte[2 + keyId.Length + NonceBytes + PlainBytes + TagBytes];
        blob[0] = FormatVersion;
        blob[1] = (byte)keyId.Length;
        keyId.CopyTo(blob, 2);
        Span<byte> nonce = blob.AsSpan(2 + keyId.Length, NonceBytes);
        RandomNumberGenerator.Fill(nonce);
        using AesGcm aes = new(loaded.Encryption[options.ActiveKeyId], TagBytes);
        aes.Encrypt(nonce, plain, blob.AsSpan(2 + keyId.Length + NonceBytes, PlainBytes), blob.AsSpan(blob.Length - TagBytes), userId.ToByteArray());
        CryptographicOperations.ZeroMemory(plain);
        return blob;
    }

    public async Task<MfaSecret?> UnprotectAsync(Guid userId, byte[]? blob, CancellationToken cancellationToken)
    {
        if (blob is null || blob.Length < 2 || blob[0] != FormatVersion)
        {
            return null;
        }

        int idLength = blob[1];
        if (blob.Length != 2 + idLength + NonceBytes + PlainBytes + TagBytes)
        {
            return null;
        }

        Keys loaded = await LoadAsync(cancellationToken);
        string keyId = Encoding.ASCII.GetString(blob, 2, idLength);
        if (!loaded.Encryption.TryGetValue(keyId, out byte[]? key))
        {
            return null;
        }

        byte[] plain = new byte[PlainBytes];
        try
        {
            using AesGcm aes = new(key, TagBytes);
            aes.Decrypt(
                blob.AsSpan(2 + idLength, NonceBytes),
                blob.AsSpan(2 + idLength + NonceBytes, PlainBytes),
                blob.AsSpan(blob.Length - TagBytes),
                plain,
                userId.ToByteArray());
            return new MfaSecret(plain[..SecretBytes], BinaryPrimitives.ReadInt64BigEndian(plain.AsSpan(SecretBytes)));
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public async Task<byte[]> RecoveryHashAsync(string normalizedCode, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(normalizedCode);
        Keys loaded = await LoadAsync(cancellationToken);
        return HMACSHA256.HashData(loaded.RecoveryPepper, Encoding.ASCII.GetBytes(normalizedCode));
    }

    public async Task<byte[]> ChallengeKeyAsync(CancellationToken cancellationToken) => (await LoadAsync(cancellationToken)).ChallengeKey;

    public void Dispose() => loadLock.Dispose();

    private async Task<Keys> LoadAsync(CancellationToken cancellationToken)
    {
        if (keys is Keys ready)
        {
            return ready;
        }

        await loadLock.WaitAsync(cancellationToken);
        try
        {
            if (keys is Keys raced)
            {
                return raced;
            }

            Dictionary<string, byte[]> encryption = new(StringComparer.Ordinal);
            foreach (string id in options.KeyIds)
            {
                encryption[id] = await ReadKeyAsync("MfaEncryptionKey-" + id, cancellationToken);
            }

            if (!encryption.TryGetValue(options.ActiveKeyId, out byte[]? active))
            {
                throw new InvalidOperationException("Mfa:ActiveKeyId is not one of Mfa:KeyIds.");
            }

            byte[] pepper = await ReadKeyAsync("MfaRecoveryPepper", cancellationToken);
            byte[] challenge = HKDF.DeriveKey(HashAlgorithmName.SHA256, active, KeyBytes, info: Encoding.ASCII.GetBytes("mfa-challenge-v1"));
            keys = new Keys(encryption, pepper, challenge);
            return keys;
        }
        finally
        {
            loadLock.Release();
        }
    }

    private async Task<byte[]> ReadKeyAsync(string name, CancellationToken cancellationToken)
    {
        string? text = await secrets.GetSecretAsync(name, cancellationToken);
        byte[]? key = null;
        try
        {
            key = text is null ? null : Convert.FromBase64String(text.Trim());
        }
        catch (FormatException)
        {
            key = null;
        }

        return key is { Length: KeyBytes }
            ? key
            : throw new InvalidOperationException("MFA secret '" + name + "' is missing or is not base64 of 32 bytes.");
    }

    private sealed record Keys(IReadOnlyDictionary<string, byte[]> Encryption, byte[] RecoveryPepper, byte[] ChallengeKey);
}
