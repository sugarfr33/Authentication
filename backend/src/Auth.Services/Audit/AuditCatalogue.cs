using System.Text.Json;
using Auth.Contracts;

namespace Auth.Services.Audit;

/// <summary>How many rows an event type produces; high-volume rows get the shorter audit retention.</summary>
public enum AuditVolume
{
    Normal,
    High,
}

/// <summary>
/// What one audit event type may hold. <paramref name="DetailKeys"/> is the allow-list of detail JSON keys: anything
/// else is dropped when the row is written. <paramref name="Reserved"/> types are not written yet (their feature does
/// not exist); they have no factory in <see cref="AuditEvents"/>.
/// </summary>
public sealed record AuditEventSpec(IReadOnlyList<string> DetailKeys, AuditVolume Volume = AuditVolume.Normal, bool Reserved = false);

/// <summary>The typed catalogue of every <see cref="AuditEventType"/>: allowed detail keys, volume, reserved or not.</summary>
public static class AuditCatalogue
{
    public static readonly IReadOnlyDictionary<AuditEventType, AuditEventSpec> Events = new Dictionary<AuditEventType, AuditEventSpec>
    {
        [AuditEventType.Registered] = new(["outcome"]),
        [AuditEventType.EmailVerified] = new([]),
        [AuditEventType.LoginSucceeded] = new([]),
        [AuditEventType.LoginFailed] = new(["reason"], AuditVolume.High),
        [AuditEventType.Lockout] = new(["until", "level"]),
        [AuditEventType.Logout] = new(["revoked"]),
        [AuditEventType.LogoutAll] = new(["revoked"]),
        [AuditEventType.TokenRefreshed] = new([], AuditVolume.High),
        [AuditEventType.TokenReuse] = new(["revoked"]),
        [AuditEventType.SessionRevoked] = new(["session", "reason"]),
        [AuditEventType.PasswordResetRequested] = new(["outcome"], AuditVolume.High),
        [AuditEventType.PasswordReset] = new([]),
        [AuditEventType.PasswordChanged] = new([]),
        [AuditEventType.MfaEnabled] = new([], Reserved: true),
        [AuditEventType.MfaVerified] = new([], Reserved: true),
        [AuditEventType.MfaFailed] = new([], Reserved: true),
        [AuditEventType.MfaRecoveryCodeUsed] = new([], Reserved: true),
        [AuditEventType.AuthorizationCodeIssued] = new(["app"]),
        [AuditEventType.AuthorizationCodeRedeemed] = new(["app", "session"]),
        [AuditEventType.SigningKeyRotated] = new([], Reserved: true),
        [AuditEventType.EmailVerificationFailed] = new(["reason"], AuditVolume.High),
        [AuditEventType.RegistrationRejected] = new(["fields"], AuditVolume.High),
        [AuditEventType.PasswordResetFailed] = new(["reason"]),
        [AuditEventType.PasswordChangeFailed] = new(["reason"]),
        [AuditEventType.RefreshRejected] = new(["reason"], AuditVolume.High),
        [AuditEventType.RoleAssigned] = new(["role", "source"]),
        [AuditEventType.RoleRemoved] = new(["role"]),
        [AuditEventType.RolePermissionRemoved] = new(["role", "permission"]),
        [AuditEventType.RegistrationDuplicate] = new([], AuditVolume.High),
        [AuditEventType.AppCreated] = new(["app", "source"]),
        [AuditEventType.AppUpdated] = new(["app", "active", "revoked"]),
        [AuditEventType.AppDeactivated] = new(["app", "revoked"]),
        [AuditEventType.AuthorizationCodeRejected] = new(["app", "reason"], AuditVolume.High),
    };

    /// <summary>
    /// The only words a string detail value may be (reasons, outcomes, field names, system role names, sources). Any
    /// other string is written as "[redacted]", so free text, a password or a token can never reach a row, even if a
    /// caller passed one by mistake.
    /// </summary>
    public static readonly IReadOnlySet<string> Words = new HashSet<string>(StringComparer.Ordinal)
    {
        // Outcomes
        "created", "sent",

        // Reasons
        "account_disabled", "already_verified", "credentials_changed", "ended_session_replayed", "expired", "inactive",
        "locked", "malformed", "mfa_not_supported", "no_password", "no_pending_password", "policy", "post_rotation_failure",
        "session_cap", "session_mismatch", "unknown", "unknown_user", "unusable_account", "unverified", "used",
        "wrong_password",

        // Registration field names
        "email", "password", "displayName",

        // System roles and assignment sources
        AuthRoles.Admin, AuthRoles.User, "bootstrap", "backfill", "registry",

        // OAuth code exchange (T19)
        "unknown_or_expired", "replayed", "client_mismatch", "redirect_mismatch", "pkce_mismatch", "inactive_client",
        "inactive_user", "invalid_request",
    };

    /// <summary>Event names (as stored in AuditLog.EventType) with <see cref="AuditVolume.High"/>.</summary>
    public static IReadOnlyList<string> HighVolumeEventNames { get; } =
        [.. Events.Where(e => e.Value.Volume == AuditVolume.High).Select(e => e.Key.ToString()).Order(StringComparer.Ordinal)];
}

/// <summary>One audit event, built only by the <see cref="AuditEvents"/> factories.</summary>
public sealed record AuditEvent
{
    internal AuditEvent(AuditEventType type, Guid? userId, params AuditField[] fields)
    {
        Type = type;
        UserId = userId;
        Fields = fields;
    }

    public AuditEventType Type { get; }

    public Guid? UserId { get; }

    internal IReadOnlyList<AuditField> Fields { get; }
}

internal sealed record AuditField(string Key, object? Value);

/// <summary>
/// Central redaction of the detail JSON: only the catalogue's keys for the type, and only values that cannot carry a
/// secret: numbers, booleans, GUIDs, UTC times, and words of <see cref="AuditCatalogue.Words"/>. Any other value is
/// written as "[redacted]". Passwords, tokens, hashes and free text therefore never reach a row.
/// </summary>
internal static class AuditDetail
{
    public const string Redacted = "[redacted]";

    public static string? Render(AuditEvent auditEvent)
    {
        AuditEventSpec spec = AuditCatalogue.Events[auditEvent.Type];
        List<AuditField> allowed = [.. auditEvent.Fields.Where(f => spec.DetailKeys.Contains(f.Key, StringComparer.Ordinal))];
        if (allowed.Count == 0)
        {
            return null;
        }

        using MemoryStream buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            foreach (AuditField field in allowed)
            {
                writer.WritePropertyName(field.Key);
                WriteValue(writer, field.Value);
            }

            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }

    public static bool IsSafeWord(string value) => AuditCatalogue.Words.Contains(value);

    private static void WriteValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case int number:
                writer.WriteNumberValue(number);
                break;
            case bool flag:
                writer.WriteBooleanValue(flag);
                break;
            case Guid id:
                writer.WriteStringValue(id.ToString("D"));
                break;
            case DateTime time when time.Kind == DateTimeKind.Utc:
                writer.WriteStringValue(time.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
                break;
            case string word:
                writer.WriteStringValue(IsSafeWord(word) ? word : Redacted);
                break;
            case IEnumerable<string> words:
                writer.WriteStartArray();
                foreach (string item in words)
                {
                    writer.WriteStringValue(IsSafeWord(item) ? item : Redacted);
                }

                writer.WriteEndArray();
                break;
            default:
                writer.WriteStringValue(Redacted);
                break;
        }
    }
}
