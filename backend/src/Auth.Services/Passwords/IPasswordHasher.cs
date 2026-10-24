namespace Auth.Services.Passwords;

/// <summary>Outcome of checking a password against a stored hash. The default value is <see cref="Failed"/>.</summary>
public enum PasswordVerifyResult
{
    /// <summary>Wrong password, or a stored value that is not a hash this service can read.</summary>
    Failed = 0,

    Success,

    /// <summary>Correct password, but the stored hash uses old parameters: store <c>Hash(password)</c> again.</summary>
    SuccessNeedsRehash,
}

/// <summary>One-way password hashing. Never stores, logs or returns the plaintext.</summary>
public interface IPasswordHasher
{
    /// <summary>Hashes with a fresh random salt and returns a self-describing string (algorithm, parameters, salt, hash).</summary>
    /// <exception cref="ArgumentException">The password is null or empty.</exception>
    string Hash(string password);

    /// <summary>Checks <paramref name="password"/> against a value produced by <see cref="Hash"/>, in constant time.</summary>
    PasswordVerifyResult Verify(string password, string storedHash);

    /// <summary>
    /// Preferred in request paths: the registered hasher waits for a hashing slot asynchronously and runs Argon2 on a
    /// worker, so queued requests do not hold threads.
    /// </summary>
    /// <exception cref="PasswordHashingBusyException">No slot freed up within the queue timeout.</exception>
    Task<string> HashAsync(string password, CancellationToken cancellationToken) => Task.FromResult(Hash(password));

    /// <inheritdoc cref="HashAsync"/>
    Task<PasswordVerifyResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken) =>
        Task.FromResult(Verify(password, storedHash));
}
