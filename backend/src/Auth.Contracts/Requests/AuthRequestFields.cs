namespace Auth.Contracts.Requests;

/// <summary>
/// JSON field names shared by the request DTOs and the API's rate-limit account key, so both read the same field.
/// </summary>
public static class AuthRequestFields
{
    /// <summary>The account email in sign-in, registration and forgot-password bodies (matched case-insensitively).</summary>
    public const string Email = "email";
}
