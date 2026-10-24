using System.Security.Cryptography;
using System.Text;
using Auth.Services.Passwords;

namespace Auth.Services.Security;

/// <summary>Outcome of a credential check. The default value is <see cref="Invalid"/>.</summary>
public enum CredentialCheck
{
    /// <summary>Unknown account, unusable account (inactive, locked) or wrong password: one generic failure.</summary>
    Invalid = 0,

    Valid,

    /// <summary>Valid, and the stored hash should be replaced with a fresh one (parameters changed).</summary>
    ValidNeedsRehash,
}

/// <summary>
/// Anti-enumeration helper for sign-in (T13). Every password check costs exactly one Argon2 Verify, whether or not the
/// account exists, is active or is locked, and every failure is the same <see cref="CredentialCheck.Invalid"/>. So the
/// unknown-user and wrong-password paths cannot be told apart by message or by work done.
/// </summary>
public interface IAuthTimingGuard
{
    /// <param name="password">The submitted password.</param>
    /// <param name="storedHash">The account's stored hash, or null when there is no account.</param>
    /// <param name="accountUsable">False for unknown, inactive or locked accounts: a dummy hash is verified instead.</param>
    CredentialCheck CheckPassword(string password, string? storedHash, bool accountUsable);
}

internal sealed class AuthTimingGuard(IPasswordHasher hasher) : IAuthTimingGuard
{
    /// <summary>
    /// Hash of a random secret with the current parameters, made once on first use. Verifying against it costs the
    /// same as verifying against a real account.
    /// </summary>
    private readonly Lazy<string> dummyHash = new(
        () => hasher.Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public CredentialCheck CheckPassword(string password, string? storedHash, bool accountUsable)
    {
        ArgumentNullException.ThrowIfNull(password);

        // Enforced before Verify and independent of the account, so it reveals nothing and bounds the hashing work.
        if (password.Length == 0 || password.Normalize(NormalizationForm.FormKC).EnumerateRunes().Count() > IPasswordPolicy.MaximumLength)
        {
            return CredentialCheck.Invalid;
        }

        bool real = accountUsable && !string.IsNullOrEmpty(storedHash);
        PasswordVerifyResult result = hasher.Verify(password, real ? storedHash! : dummyHash.Value);

        if (!real)
        {
            return CredentialCheck.Invalid;
        }

        return result switch
        {
            PasswordVerifyResult.Success => CredentialCheck.Valid,
            PasswordVerifyResult.SuccessNeedsRehash => CredentialCheck.ValidNeedsRehash,
            _ => CredentialCheck.Invalid,
        };
    }
}
