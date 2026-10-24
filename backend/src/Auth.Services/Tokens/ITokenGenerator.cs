using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Services.Tokens;

/// <summary>An opaque token: the raw value goes to the client once; only the hash is ever stored.</summary>
public sealed record GeneratedToken(string Value, byte[] Hash);

/// <summary>Opaque random tokens for refresh, password reset and email verification.</summary>
public interface ITokenGenerator
{
    /// <summary>256 bits from the OS CSPRNG, base64url-encoded (43 characters), with its SHA-256 hash.</summary>
    GeneratedToken Generate();

    /// <summary>SHA-256 of the token text (UTF-8), the value stored and looked up.</summary>
    byte[] Hash(string value);
}

internal sealed class TokenGenerator : ITokenGenerator
{
    public const int EntropyBytes = 32;

    public GeneratedToken Generate()
    {
        string value = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(EntropyBytes));
        return new GeneratedToken(value, Hash(value));
    }

    public byte[] Hash(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return SHA256.HashData(Encoding.UTF8.GetBytes(value));
    }
}
