namespace Auth.Services.Passwords;

/// <summary>
/// Thrown when no hashing slot frees up within the queue timeout. The host answers 503 with Retry-After instead of
/// letting concurrent Argon2 calls (64 MiB each) exhaust memory.
/// </summary>
public sealed class PasswordHashingBusyException : Exception
{
    public PasswordHashingBusyException()
        : base("All password hashing slots are busy.")
    {
    }

    public PasswordHashingBusyException(string message)
        : base(message)
    {
    }

    public PasswordHashingBusyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Limits on concurrent hash and verify operations.</summary>
public sealed class PasswordHashingLimits
{
    /// <summary>Default: half the processors (at least 1, at most 16). Peak memory is about this times 64 MiB.</summary>
    public int MaxConcurrentOperations { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 16);

    /// <summary>How long a request waits for a slot before PasswordHashingBusyException.</summary>
    public TimeSpan QueueTimeout { get; init; } = TimeSpan.FromSeconds(5);

    internal PasswordHashingLimits Validated()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxConcurrentOperations, 1, nameof(MaxConcurrentOperations));
        ArgumentOutOfRangeException.ThrowIfLessThan(QueueTimeout, TimeSpan.Zero, nameof(QueueTimeout));
        return this;
    }
}

/// <summary>Wraps the Argon2 hasher with a semaphore, so at most N hash or verify operations run at once.</summary>
internal sealed class BoundedPasswordHasher(IPasswordHasher inner, PasswordHashingLimits limits) : IPasswordHasher, IDisposable
{
    private readonly SemaphoreSlim slots = new(limits.MaxConcurrentOperations, limits.MaxConcurrentOperations);

    public string Hash(string password) => Run(() => inner.Hash(password));

    public PasswordVerifyResult Verify(string password, string storedHash) => Run(() => inner.Verify(password, storedHash));

    public void Dispose() => slots.Dispose();

    private T Run<T>(Func<T> operation)
    {
        if (!slots.Wait(limits.QueueTimeout))
        {
            throw new PasswordHashingBusyException();
        }

        try
        {
            return operation();
        }
        finally
        {
            slots.Release();
        }
    }
}
