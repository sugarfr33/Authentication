namespace Auth.DAL;

/// <summary>
/// A row changed or disappeared since it was read (RowVersion mismatch on User or RefreshToken).
/// Mapped from EF Core's DbUpdateConcurrencyException.
/// </summary>
public class ConcurrencyConflictException : DataAccessException
{
    public ConcurrencyConflictException()
    {
    }

    public ConcurrencyConflictException(string message)
        : base(message)
    {
    }

    public ConcurrencyConflictException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
