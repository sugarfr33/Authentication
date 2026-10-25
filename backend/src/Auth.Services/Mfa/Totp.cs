using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Services.Mfa;

/// <summary>
/// RFC 6238 TOTP (HMAC-SHA1, 30-second steps from the Unix epoch) with RFC 4226 dynamic truncation, written on
/// System.Security.Cryptography only (no OTP package). Codes are compared in constant time.
/// </summary>
internal static class Totp
{
    public const int StepSeconds = 30;
    public const int Digits = 6;

    /// <summary>Accepted drift: the previous, current and next step.</summary>
    public const int Window = 1;

    public static long StepAt(DateTime utc) => (long)Math.Floor((utc - DateTime.UnixEpoch).TotalSeconds / StepSeconds);

    /// <summary>The code for one step, zero-padded to <paramref name="digits"/>.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Security",
        "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "RFC 6238 TOTP as implemented by every authenticator app is HMAC-SHA1; HMAC-SHA1 is not affected by SHA-1 collisions.")]
    public static string Compute(ReadOnlySpan<byte> secret, long step, int digits = Digits)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> mac = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, mac);
        int offset = mac[^1] & 0x0F;
        int binary = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
        int modulo = 1;
        for (int i = 0; i < digits; i++)
        {
            modulo *= 10;
        }

        return (binary % modulo).ToString("D" + digits, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The step a well-formed 6-digit <paramref name="code"/> matches within the window around <paramref name="currentStep"/>,
    /// only among steps later than <paramref name="lastUsedStep"/> (replay protection); null otherwise. Every candidate is
    /// computed and compared in constant time, without an early exit.
    /// </summary>
    public static long? Match(ReadOnlySpan<byte> secret, string? code, long currentStep, long lastUsedStep)
    {
        string? normalized = Normalize(code);
        if (normalized is null)
        {
            return null;
        }

        byte[] presented = Encoding.ASCII.GetBytes(normalized);
        long? matched = null;
        for (long step = currentStep - Window; step <= currentStep + Window; step++)
        {
            bool equal = CryptographicOperations.FixedTimeEquals(presented, Encoding.ASCII.GetBytes(Compute(secret, step)));
            if (equal && step > lastUsedStep && matched is null)
            {
                matched = step;
            }
        }

        return matched;
    }

    /// <summary>True when the code is well formed and matches a step that was already used (for the audit reason only).</summary>
    public static bool IsReplay(ReadOnlySpan<byte> secret, string? code, long currentStep, long lastUsedStep)
    {
        string? normalized = Normalize(code);
        if (normalized is null)
        {
            return false;
        }

        for (long step = currentStep - Window; step <= Math.Min(currentStep + Window, lastUsedStep); step++)
        {
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(normalized), Encoding.ASCII.GetBytes(Compute(secret, step))))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Exactly six ASCII digits after removing spaces, or null.</summary>
    internal static string? Normalize(string? code)
    {
        if (code is null || code.Length > 16)
        {
            return null;
        }

        string compact = code.Replace(" ", string.Empty, StringComparison.Ordinal);
        return compact.Length == Digits && compact.All(char.IsAsciiDigit) ? compact : null;
    }
}

/// <summary>RFC 4648 base32 (upper case, no padding), for the manual-entry key and the otpauth URI.</summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        StringBuilder output = new((data.Length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        foreach (byte value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return output.ToString();
    }
}
