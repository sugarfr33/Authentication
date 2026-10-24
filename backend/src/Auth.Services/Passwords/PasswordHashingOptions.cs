namespace Auth.Services.Passwords;

/// <summary>
/// Argon2id cost parameters for new hashes. Defaults follow plan assumption A9 (m = 64 MiB, t = 3, p = 1).
/// Stored hashes carry their own parameters, so raising these later only triggers a rehash on the next login.
/// Lower values are for tests only; register a different instance before AddAuthServices to override.
/// </summary>
public sealed class PasswordHashingOptions
{
    /// <summary>Memory cost in KiB (65536 = 64 MiB).</summary>
    public int MemorySizeKiB { get; init; } = 65536;

    public int Iterations { get; init; } = 3;

    public int Parallelism { get; init; } = 1;

    public int SaltSizeBytes { get; init; } = 16;

    public int HashSizeBytes { get; init; } = 32;
}
