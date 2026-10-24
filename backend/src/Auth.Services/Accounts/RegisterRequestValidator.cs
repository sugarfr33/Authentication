using System.Net.Mail;
using Auth.Contracts.Requests;
using Auth.Services.Passwords;

namespace Auth.Services.Accounts;

/// <summary>
/// Hand-written validation of <see cref="RegisterRequest"/> (no validation package). Errors are keyed by the JSON
/// field name, ready for a ValidationProblem response. Validation never looks at the database, so its answer is the
/// same whether or not the email is already registered.
/// </summary>
internal sealed class RegisterRequestValidator(IPasswordPolicy passwordPolicy)
{
    public const int DisplayNameMaxLength = 128;

    /// <summary>RFC 5321 limit for the part before the @.</summary>
    private const int LocalPartMaxLength = 64;

    /// <summary>Raw length above which the password is refused before the policy normalizes (copies) it.</summary>
    private const int MaxRawPasswordLength = 1024;

    public IReadOnlyDictionary<string, string[]> Validate(RegisterRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        Dictionary<string, string[]> errors = new(StringComparer.Ordinal);

        string email = request.Email?.Trim() ?? string.Empty;
        if (email.Length == 0)
        {
            errors[AuthRequestFields.Email] = ["Email is required."];
        }
        else if (!IsValidEmail(email))
        {
            errors[AuthRequestFields.Email] = ["Email is not a valid address."];
        }

        string[] passwordErrors = PasswordErrors(request.Password, email);
        if (passwordErrors.Length > 0)
        {
            errors["password"] = passwordErrors;
        }

        string displayName = request.DisplayName?.Trim() ?? string.Empty;
        if (displayName.Length == 0)
        {
            errors["displayName"] = ["Display name is required."];
        }
        else if (displayName.Length > DisplayNameMaxLength || displayName.Any(char.IsControl))
        {
            errors["displayName"] = ["Display name must be at most 128 characters, without control characters."];
        }

        return errors;
    }

    internal static bool IsValidEmail(string email)
    {
        int at = email.IndexOf('@', StringComparison.Ordinal);
        if (email.Length > EmailNormalizer.MaxLength || at <= 0 || at > LocalPartMaxLength || at != email.LastIndexOf('@') || at == email.Length - 1)
        {
            return false;
        }

        string domain = email[(at + 1)..];
        if (email.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))
            || !domain.Contains('.', StringComparison.Ordinal)
            || domain.StartsWith('.')
            || domain.EndsWith('.')
            || domain.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        return MailAddress.TryCreate(email, out MailAddress? address) && address.Address == email && address.DisplayName.Length == 0;
    }

    private string[] PasswordErrors(string? password, string email)
    {
        if (string.IsNullOrEmpty(password))
        {
            return ["Password is required."];
        }

        if (password.Length > MaxRawPasswordLength)
        {
            return [Message(PasswordPolicyViolation.TooLong)];
        }

        return [.. passwordPolicy.Validate(password, email).Select(Message)];
    }

    private static string Message(PasswordPolicyViolation violation) => violation switch
    {
        PasswordPolicyViolation.TooShort => "Password must be at least 12 characters.",
        PasswordPolicyViolation.TooLong => "Password must be at most 128 characters.",
        PasswordPolicyViolation.Common => "Password is too common; choose a less predictable one.",
        PasswordPolicyViolation.MatchesEmail => "Password must not be the same as the email address.",
        _ => "Password is not allowed.",
    };
}
