using Auth.Entities;

namespace Auth.Services.Tokens;

/// <summary>
/// Pure rotation rules over SigningKey rows at a given instant (plan A6). The SigningKey status column only allows
/// Active, Retiring and Retired, so a key that is published but not yet signing is an Active row whose ActivatedUtc is
/// in the future.
/// <list type="bullet">
/// <item>Signs: Active, ActivatedUtc &lt;= now; the latest activation wins.</item>
/// <item>Published in the JWKS: every Active key (future ones included), and Retiring keys until RetireAfterUtc.</item>
/// <item>Retired keys are never published.</item>
/// </list>
/// </summary>
internal static class SigningKeySchedule
{
    public static SigningKey? CurrentSigningKey(IEnumerable<SigningKey> keys, DateTime utcNow) =>
        keys.Where(k => k.Status == SigningKeyStatus.Active && k.ActivatedUtc is not null && k.ActivatedUtc <= utcNow)
            .OrderByDescending(k => k.ActivatedUtc)
            .ThenByDescending(k => k.Kid, StringComparer.Ordinal)
            .FirstOrDefault();

    public static IReadOnlyList<SigningKey> Published(IEnumerable<SigningKey> keys, DateTime utcNow) =>
        keys.Where(k => IsPublished(k, utcNow))
            .OrderBy(k => k.Kid, StringComparer.Ordinal)
            .ToList();

    public static bool IsPublished(SigningKey key, DateTime utcNow) =>
        key.Status == SigningKeyStatus.Active
        || (key.Status == SigningKeyStatus.Retiring && key.RetireAfterUtc is not null && key.RetireAfterUtc > utcNow);
}
