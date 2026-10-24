namespace Auth.DAL;

/// <summary>A save failed in the database. Services see this instead of EF Core exception types.</summary>
public class DataAccessException : Exception
{
    public DataAccessException()
    {
    }

    public DataAccessException(string message)
        : base(message)
    {
    }

    public DataAccessException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
