using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Auth.Services.Passwords;

/// <summary>
/// Argon2id (RFC 9106) hasher. Stored format is the PHC string <c>$argon2id$v=19$m=65536,t=3,p=1$salt$hash</c>
/// (unpadded base64), so the parameters travel with each hash.
/// Passwords are NFKC-normalized before hashing (NIST SP 800-63B), so equivalent Unicode input matches.
/// </summary>
internal sealed class Argon2PasswordHasher(PasswordHashingOptions options) : IPasswordHasher
{
    private const string Prefix = "$argon2id$v=19$";

    // Upper bounds (256 MiB, t=6, p=4) accepted from a stored hash, so a tampered row cannot make Verify allocate
    // unbounded memory or time. The configured options must stay within them too, or new hashes would never verify.
    internal const int MaxMemorySizeKiB = 262144;
    internal const int MaxIterations = 6;
    internal const int MaxParallelism = 4;
    private const int MaxBytes = 1024;

    private readonly PasswordHashingOptions options = EnsureWithinCaps(options);

    public string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] salt = RandomNumberGenerator.GetBytes(options.SaltSizeBytes);
        byte[] hash = Derive(password, salt, options.MemorySizeKiB, options.Iterations, options.Parallelism, options.HashSizeBytes);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{Prefix}m={options.MemorySizeKiB},t={options.Iterations},p={options.Parallelism}${ToBase64(salt)}${ToBase64(hash)}");
    }

    public PasswordVerifyResult Verify(string password, string storedHash)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length == 0 || !TryParse(storedHash, out Parameters stored))
        {
            return PasswordVerifyResult.Failed;
        }

        byte[] actual = Derive(password, stored.Salt, stored.MemorySizeKiB, stored.Iterations, stored.Parallelism, stored.Hash.Length);
        if (!CryptographicOperations.FixedTimeEquals(actual, stored.Hash))
        {
            return PasswordVerifyResult.Failed;
        }

        bool current = stored.MemorySizeKiB == options.MemorySizeKiB
            && stored.Iterations == options.Iterations
            && stored.Parallelism == options.Parallelism
            && stored.Salt.Length == options.SaltSizeBytes
            && stored.Hash.Length == options.HashSizeBytes;

        return current ? PasswordVerifyResult.Success : PasswordVerifyResult.SuccessNeedsRehash;
    }

    private static PasswordHashingOptions EnsureWithinCaps(PasswordHashingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Parallelism, 1, nameof(options));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Parallelism, MaxParallelism, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MemorySizeKiB, 8 * options.Parallelism, nameof(options));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MemorySizeKiB, MaxMemorySizeKiB, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Iterations, 1, nameof(options));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Iterations, MaxIterations, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.SaltSizeBytes, 16, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.HashSizeBytes, 32, nameof(options));
        return options;
    }

    private static byte[] Derive(string password, byte[] salt, int memorySizeKiB, int iterations, int parallelism, int length)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormKC));
        try
        {
            using Argon2id argon2 = new(passwordBytes)
            {
                Salt = salt,
                MemorySize = memorySizeKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };
            return argon2.GetBytes(length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>Strict parser for the PHC string this class writes. Anything else, or out-of-bounds parameters, is rejected.</summary>
    private static bool TryParse(string? value, out Parameters parameters)
    {
        parameters = default;
        if (value is null || !value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string[] parts = value[Prefix.Length..].Split('$');
        if (parts.Length != 3)
        {
            return false;
        }

        string[] costs = parts[0].Split(',');
        if (costs.Length != 3
            || !TryReadCost(costs[0], "m=", 8, MaxMemorySizeKiB, out int memory)
            || !TryReadCost(costs[1], "t=", 1, MaxIterations, out int iterations)
            || !TryReadCost(costs[2], "p=", 1, MaxParallelism, out int parallelism)
            || memory < 8 * parallelism)
        {
            return false;
        }

        if (!TryFromBase64(parts[1], out byte[] salt) || salt.Length < 8
            || !TryFromBase64(parts[2], out byte[] hash) || hash.Length < 16)
        {
            return false;
        }

        parameters = new Parameters(memory, iterations, parallelism, salt, hash);
        return true;
    }

    private static bool TryReadCost(string part, string name, int min, int max, out int value)
    {
        value = 0;
        return part.StartsWith(name, StringComparison.Ordinal)
            && int.TryParse(part.AsSpan(name.Length), NumberStyles.None, CultureInfo.InvariantCulture, out value)
            && value >= min
            && value <= max;
    }

    private static string ToBase64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static bool TryFromBase64(string text, out byte[] bytes)
    {
        bytes = [];
        if (text.Length == 0 || text.Length > MaxBytes * 2)
        {
            return false;
        }

        string padded = text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '=');
        byte[] buffer = new byte[padded.Length];
        if (!Convert.TryFromBase64String(padded, buffer, out int written))
        {
            return false;
        }

        bytes = buffer[..written];
        return true;
    }

    private readonly record struct Parameters(int MemorySizeKiB, int Iterations, int Parallelism, byte[] Salt, byte[] Hash);
}
