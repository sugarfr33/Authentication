namespace Auth.Services.Accounts;

/// <summary>Configuration section <c>AccountEmail</c>: links and lifetimes for account emails.</summary>
public sealed class AccountEmailOptions
{
    public const string SectionName = "AccountEmail";

    /// <summary>
    /// Front-end page that confirms the address. The token is appended as a URL fragment (<c>#token=...</c>), so it
    /// never reaches a server log or a Referer header; the page posts it to <c>/api/v1/auth/verify-email</c>.
    /// </summary>
    public Uri VerifyEmailUrl { get; set; } = new("https://localhost:5173/verify-email");

    /// <summary>How long a verification link stays valid. 1 minute to 7 days.</summary>
    public TimeSpan VerificationTokenLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Front-end page that sets a new password. The token is appended as a URL fragment (<c>#token=...</c>); the page
    /// posts it with the new password to <c>/api/v1/auth/reset-password</c>.
    /// </summary>
    public Uri ResetPasswordUrl { get; set; } = new("https://localhost:5173/reset-password");

    /// <summary>How long a password reset link stays valid. 5 to 60 minutes.</summary>
    public TimeSpan ResetTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Throws when a value is out of range; returns this instance for chaining.</summary>
    public AccountEmailOptions Validated()
    {
        if (!VerifyEmailUrl.IsAbsoluteUri || VerifyEmailUrl.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(VerifyEmailUrl.Fragment))
        {
            throw new ArgumentOutOfRangeException(nameof(VerifyEmailUrl), "AccountEmail:VerifyEmailUrl must be an absolute http(s) URL without a fragment.");
        }

        if (!ResetPasswordUrl.IsAbsoluteUri || ResetPasswordUrl.Scheme is not ("https" or "http") || !string.IsNullOrEmpty(ResetPasswordUrl.Fragment))
        {
            throw new ArgumentOutOfRangeException(nameof(ResetPasswordUrl), "AccountEmail:ResetPasswordUrl must be an absolute http(s) URL without a fragment.");
        }

        if (ResetTokenLifetime < TimeSpan.FromMinutes(5) || ResetTokenLifetime > TimeSpan.FromMinutes(60))
        {
            throw new ArgumentOutOfRangeException(nameof(ResetTokenLifetime), "AccountEmail:ResetTokenLifetime must be 5 to 60 minutes.");
        }

        if (VerificationTokenLifetime < TimeSpan.FromMinutes(1) || VerificationTokenLifetime > TimeSpan.FromDays(7))
        {
            throw new ArgumentOutOfRangeException(nameof(VerificationTokenLifetime), "AccountEmail:VerificationTokenLifetime must be 1 minute to 7 days.");
        }

        return this;
    }

    internal string VerificationLink(string token) => VerifyEmailUrl.AbsoluteUri + "#token=" + token;

    internal string ResetLink(string token) => ResetPasswordUrl.AbsoluteUri + "#token=" + token;
}
