namespace Auth.DAL;

/// <summary>An insert or update hit a unique index or key, for example a second user with the same normalized email.</summary>
public class UniqueConstraintViolationException : DataAccessException
{
    public UniqueConstraintViolationException()
    {
    }

    public UniqueConstraintViolationException(string message)
        : base(message)
    {
    }

    public UniqueConstraintViolationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public UniqueConstraintViolationException(string? constraintName, string message, Exception innerException)
        : base(message, innerException)
    {
        ConstraintName = constraintName;
    }

    /// <summary>The violated index or constraint, such as <c>UQ_User_NormalizedEmail</c>, when SQL Server reports it.</summary>
    public string? ConstraintName { get; }
}
