namespace Auth.Api.RateLimiting;

/// <summary>The rate-limited auth operations. Endpoints are matched to a kind by path (see <see cref="AuthRateLimitOptions.Paths"/>).</summary>
public enum AuthRateLimitKind
{
    Login = 1,
    Refresh,
    Register,
    ForgotPassword,
    ResetPassword,
}

/// <summary>A fixed-window limit: <see cref="PermitLimit"/> requests per <see cref="Window"/>.</summary>
public sealed class RateLimitRule
{
    public int PermitLimit { get; set; }

    public TimeSpan Window { get; set; }
}

/// <summary>Limits for one kind: always per client IP, optionally also per account (normalized email from the body).</summary>
public sealed class AuthRateLimitPolicy
{
    public RateLimitRule PerIp { get; set; } = new();

    public RateLimitRule? PerAccount { get; set; }
}

/// <summary>Configuration section <c>RateLimiting</c>.</summary>
public sealed class AuthRateLimitOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>
    /// Request path (exact, case-insensitive) to kind. The defaults are the T12/T13 endpoint paths, so the limits
    /// apply as soon as those endpoints exist. More paths can be added by configuration.
    /// </summary>
    public Dictionary<string, AuthRateLimitKind> Paths { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["/api/v1/auth/login"] = AuthRateLimitKind.Login,
        ["/api/v1/auth/refresh"] = AuthRateLimitKind.Refresh,
        ["/api/v1/auth/register"] = AuthRateLimitKind.Register,
        ["/api/v1/auth/forgot-password"] = AuthRateLimitKind.ForgotPassword,
        ["/api/v1/auth/reset-password"] = AuthRateLimitKind.ResetPassword,
    };

    public Dictionary<AuthRateLimitKind, AuthRateLimitPolicy> Policies { get; } = new()
    {
        [AuthRateLimitKind.Login] = Policy(20, TimeSpan.FromMinutes(1), 10, TimeSpan.FromMinutes(15)),
        [AuthRateLimitKind.Refresh] = Policy(60, TimeSpan.FromMinutes(1), null, TimeSpan.Zero),
        [AuthRateLimitKind.Register] = Policy(10, TimeSpan.FromHours(1), 3, TimeSpan.FromHours(1)),
        [AuthRateLimitKind.ForgotPassword] = Policy(10, TimeSpan.FromMinutes(15), 3, TimeSpan.FromMinutes(15)),
        [AuthRateLimitKind.ResetPassword] = Policy(10, TimeSpan.FromMinutes(15), null, TimeSpan.Zero),
    };

    /// <summary>
    /// At most this many body bytes are read to find the account email. A larger or chunked body is only IP-limited;
    /// the body is never buffered in memory beyond this size.
    /// </summary>
    public int MaxAccountBodyBytes { get; set; } = 16 * 1024;

    internal bool IsValid() =>
        MaxAccountBodyBytes is > 0 and <= 1024 * 1024
        && Policies.Values.All(p => IsValid(p.PerIp) && (p.PerAccount is null || IsValid(p.PerAccount)));

    internal AuthRateLimitKind? Resolve(PathString path)
    {
        string value = (path.Value ?? string.Empty).TrimEnd('/');
        return Paths.TryGetValue(value, out AuthRateLimitKind kind) ? kind : null;
    }

    private static bool IsValid(RateLimitRule rule) => rule.PermitLimit > 0 && rule.Window > TimeSpan.Zero;

    private static AuthRateLimitPolicy Policy(int ipLimit, TimeSpan ipWindow, int? accountLimit, TimeSpan accountWindow) => new()
    {
        PerIp = new RateLimitRule { PermitLimit = ipLimit, Window = ipWindow },
        PerAccount = accountLimit is null ? null : new RateLimitRule { PermitLimit = accountLimit.Value, Window = accountWindow },
    };
}
