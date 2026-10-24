namespace Auth.Services.Tokens;

/// <summary>Access-token and signing-key settings (plan A6/A8).</summary>
public sealed class TokenOptions
{
    /// <summary>Upper bound for <see cref="ClockSkew"/> (T07 acceptance).</summary>
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>The <c>iss</c> claim and the only issuer accepted when validating. Configuration key <c>Auth:Issuer</c>.</summary>
    public required string Issuer { get; init; }

    /// <summary>The <c>aud</c> for tokens not issued to a client application (central auth itself). Configuration key <c>Auth:Audience</c>; defaults to the issuer.</summary>
    public string? Audience { get; init; }

    public string DefaultAudience => string.IsNullOrWhiteSpace(Audience) ? Issuer : Audience;

    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(15);

    public TimeSpan ClockSkew { get; init; } = MaxClockSkew;

    /// <summary>How long the published keys and loaded key material are cached before the database is read again.</summary>
    public TimeSpan KeyCacheDuration { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The minimum time a key must be published before it may sign, and stay published after it stops signing:
    /// one token lifetime plus skew, so every token in circulation always finds its key in the JWKS.
    /// </summary>
    public TimeSpan KeyOverlap => AccessTokenLifetime + ClockSkew;

    internal TokenOptions Validated()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Issuer, nameof(Issuer));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(AccessTokenLifetime, TimeSpan.Zero, nameof(AccessTokenLifetime));
        ArgumentOutOfRangeException.ThrowIfLessThan(ClockSkew, TimeSpan.Zero, nameof(ClockSkew));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ClockSkew, MaxClockSkew, nameof(ClockSkew));
        ArgumentOutOfRangeException.ThrowIfLessThan(KeyCacheDuration, TimeSpan.Zero, nameof(KeyCacheDuration));
        return this;
    }
}
