namespace Auth.Contracts.Requests;

/// <summary>
/// The one email normalization of the system: <c>User.NormalizedEmail</c>, the per-account rate-limit key and every
/// endpoint that looks an account up by email all use it, so they always agree on which account a value means.
/// </summary>
public static class EmailNormalizer
{
    /// <summary>Longest email accepted anywhere (the User.Email and User.NormalizedEmail column size).</summary>
    public const int MaxLength = 256;

    /// <summary>Trimmed and upper-cased (invariant culture). Returns null when blank or longer than <see cref="MaxLength"/>.</summary>
    public static string? Normalize(string? email)
    {
        string? trimmed = email?.Trim();
        return string.IsNullOrEmpty(trimmed) || trimmed.Length > MaxLength ? null : trimmed.ToUpperInvariant();
    }
}
