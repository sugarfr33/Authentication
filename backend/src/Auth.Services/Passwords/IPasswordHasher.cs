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
}
