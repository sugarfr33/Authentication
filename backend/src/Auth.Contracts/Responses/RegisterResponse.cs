namespace Auth.Contracts.Responses;

/// <summary>Answer to every valid sign-up (202), identical whether or not the email already had an account.</summary>
public sealed record RegisterResponse(string Message);
