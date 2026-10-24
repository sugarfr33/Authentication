using System.Text;

namespace Auth.Services.Passwords;

/// <summary>
/// NIST SP 800-63B style policy: length (counted in Unicode code points, after NFKC), a block list of common
/// passwords, and the user's email local part. No composition rules (digits, symbols), as NIST recommends.
/// </summary>
internal sealed class PasswordPolicy(CommonPasswordList commonPasswords) : IPasswordPolicy
{
    public IReadOnlyList<PasswordPolicyViolation> Validate(string password, string? email)
    {
        ArgumentNullException.ThrowIfNull(password);

        string normalized = password.Normalize(NormalizationForm.FormKC);
        int length = normalized.EnumerateRunes().Count();
        List<PasswordPolicyViolation> violations = [];

        if (length < IPasswordPolicy.MinimumLength)
        {
            violations.Add(PasswordPolicyViolation.TooShort);
        }

        if (length > IPasswordPolicy.MaximumLength)
        {
            violations.Add(PasswordPolicyViolation.TooLong);
        }

        if (commonPasswords.Contains(normalized))
        {
            violations.Add(PasswordPolicyViolation.Common);
        }

        string? localPart = EmailLocalPart(email);
        if (localPart is not null && string.Equals(normalized, localPart, StringComparison.OrdinalIgnoreCase))
        {
            violations.Add(PasswordPolicyViolation.MatchesEmail);
        }

        return violations;
    }

    private static string? EmailLocalPart(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        int at = email.LastIndexOf('@');
        string local = (at > 0 ? email[..at] : email).Trim().Normalize(NormalizationForm.FormKC);
        return local.Length == 0 ? null : local;
    }
}
