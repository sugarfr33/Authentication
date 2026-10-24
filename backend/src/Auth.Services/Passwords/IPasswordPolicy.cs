namespace Auth.Services.Passwords;

/// <summary>Why a candidate password was rejected. Carries no part of the password itself.</summary>
public enum PasswordPolicyViolation
{
    TooShort = 1,
    TooLong,

    /// <summary>On the bundled list of common or breached passwords (case-insensitive).</summary>
    Common,

    /// <summary>Equal to the local part of the user's email address (case-insensitive).</summary>
    MatchesEmail,
}

/// <summary>Rules for new passwords (registration, reset, change).</summary>
public interface IPasswordPolicy
{
    public const int MinimumLength = 12;

    /// <summary>Upper bound so a request cannot submit megabytes of "password" to the hasher.</summary>
    public const int MaximumLength = 128;

    /// <summary>Returns every violated rule; an empty list means the password is acceptable.</summary>
    /// <param name="password">The candidate password.</param>
    /// <param name="email">The user's email, when known, to reject passwords equal to its local part.</param>
    IReadOnlyList<PasswordPolicyViolation> Validate(string password, string? email);
}
