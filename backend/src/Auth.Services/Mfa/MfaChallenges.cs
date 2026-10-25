using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Auth.Entities;
using Auth.Services.Common;

namespace Auth.Services.Mfa;

/// <summary>
/// The login challenge (docs/mfa-totp.md section 5): proof that the password was right, valid for
/// MfaOptions.ChallengeLifetime, carried in the HttpOnly, host-only <c>__Secure-mfa</c> cookie (not <c>__Host-</c>: that prefix forces Path=/). Stateless: base64url of user id,
/// expiry and an HMAC-SHA256 over them plus SHA-256 of the user's SecurityStamp, of the current secret blob and of the
/// User-Agent. Every successful second factor rewrites the blob, so a challenge works once.
/// </summary>
internal interface IMfaChallenges
{
    Task<string> CreateAsync(User user, string? userAgent, CancellationToken cancellationToken);

    /// <summary>The user the challenge names when it is well formed and not expired (its MAC is checked by <see cref="VerifyAsync"/>).</summary>
    Guid? ReadUserId(string? challenge);

    /// <summary>True when the MAC matches this user's current state and this User-Agent (constant-time comparison).</summary>
    Task<bool> VerifyAsync(string challenge, User user, string? userAgent, CancellationToken cancellationToken);
}

internal sealed class MfaChallenges(IMfaCrypto crypto, MfaOptions options, IClock clock) : IMfaChallenges
{
    private const int PayloadBytes = 16 + 8;
    private const int MacBytes = 32;

    public async Task<string> CreateAsync(User user, string? userAgent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        byte[] token = new byte[PayloadBytes + MacBytes];
        user.Id.ToByteArray().CopyTo(token, 0);
        BinaryPrimitives.WriteInt64BigEndian(token.AsSpan(16), new DateTimeOffset(clock.UtcNow + options.ChallengeLifetime).ToUnixTimeSeconds());
        (await MacAsync(token.AsSpan(0, PayloadBytes).ToArray(), user, userAgent, cancellationToken)).CopyTo(token, PayloadBytes);
        return Base64Url(token);
    }

    public Guid? ReadUserId(string? challenge)
    {
        byte[]? token = Decode(challenge);
        if (token is null)
        {
            return null;
        }

        long expires = BinaryPrimitives.ReadInt64BigEndian(token.AsSpan(16, 8));
        return DateTimeOffset.FromUnixTimeSeconds(Math.Clamp(expires, 0, 253402300799)).UtcDateTime > clock.UtcNow
            ? new Guid(token.AsSpan(0, 16))
            : null;
    }

    public async Task<bool> VerifyAsync(string challenge, User user, string? userAgent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        byte[]? token = Decode(challenge);
        if (token is null || ReadUserId(challenge) != user.Id)
        {
            return false;
        }

        byte[] expected = await MacAsync(token.AsSpan(0, PayloadBytes).ToArray(), user, userAgent, cancellationToken);
        return CryptographicOperations.FixedTimeEquals(expected, token.AsSpan(PayloadBytes, MacBytes));
    }

    private async Task<byte[]> MacAsync(byte[] payload, User user, string? userAgent, CancellationToken cancellationToken)
    {
        byte[] key = await crypto.ChallengeKeyAsync(cancellationToken);
        byte[] input = [
            .. payload,
            .. SHA256.HashData(user.SecurityStamp.ToByteArray()),
            .. SHA256.HashData(user.MfaSecretEncrypted ?? []),
            .. SHA256.HashData(Encoding.UTF8.GetBytes(userAgent ?? string.Empty)),
        ];
        return HMACSHA256.HashData(key, input);
    }

    private static byte[]? Decode(string? challenge)
    {
        if (string.IsNullOrEmpty(challenge) || challenge.Length > 128)
        {
            return null;
        }

        try
        {
            string padded = challenge.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - (padded.Length % 4)) % 4);
            byte[] token = Convert.FromBase64String(padded);
            return token.Length == PayloadBytes + MacBytes ? token : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
