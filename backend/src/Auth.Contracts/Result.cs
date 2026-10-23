namespace Auth.Contracts;

/// <summary>Outcome of an operation that returns no value: success, or one <see cref="AuthError"/>.</summary>
public sealed class Result
{
    private static readonly Result SuccessInstance = new(null);

    private Result(AuthError? error)
    {
        Error = error;
    }

    public bool IsSuccess => Error is null;

    public AuthError? Error { get; }

    public static Result Success() => SuccessInstance;

    public static Result Failure(AuthError error) => new(error);

    public static Result<T> Success<T>(T value) => new(value, null);

    public static Result<T> Failure<T>(AuthError error) => new(default, error);
}

/// <summary>Outcome of an operation that returns a <typeparamref name="T"/> on success, or one <see cref="AuthError"/>.</summary>
public sealed class Result<T>
{
    internal Result(T? value, AuthError? error)
    {
        Value = value;
        Error = error;
    }

    public bool IsSuccess => Error is null;

    /// <summary>The value; only meaningful when <see cref="IsSuccess"/> is true.</summary>
    public T? Value { get; }

    public AuthError? Error { get; }
}
