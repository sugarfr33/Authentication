namespace Auth.Services.ClientApplications;

/// <summary>
/// A refresh family was requested for an unknown or inactive client application (for example one deactivated between a
/// caller's check and the issue). Callers map it to InvalidClient.
/// </summary>
public sealed class InactiveClientApplicationException : InvalidOperationException
{
    public InactiveClientApplicationException()
        : base("Refresh tokens are not issued for an unknown or inactive client application.")
    {
    }

    public InactiveClientApplicationException(string message)
        : base(message)
    {
    }

    public InactiveClientApplicationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
