using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace Auth.Api.Logging;

/// <summary>
/// Redaction policy for every log event: passwords, tokens, cookies, Authorization values, secrets and connection
/// strings never reach a sink. Properties with a sensitive name are replaced outright; every other string value is
/// scrubbed of credential-shaped fragments (Bearer values, key=value pairs, JWTs).
/// </summary>
internal static partial class LogRedaction
{
    public const string Mask = "[REDACTED]";

    private static readonly string[] SensitiveNameParts =
    [
        "password", "passwd", "pwd", "secret", "token", "authorization", "cookie", "connectionstring",
        "apikey", "api_key", "api-key", "credential", "privatekey", "private_key", "otp", "recoverycode",
    ];

    public static bool IsSensitiveName(string name) =>
        SensitiveNameParts.Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase));

    public static string Redact(string text)
    {
        string result = AuthorizationValue().Replace(text, "$1 " + Mask);
        result = SensitivePair().Replace(result, "$1=" + Mask);
        result = Jwt().Replace(result, Mask);
        result = PasswordHash().Replace(result, Mask);
        result = LongOpaqueValue().Replace(result, Mask);
        return result;
    }

    [GeneratedRegex(@"(?i)\b(bearer|basic|negotiate)\s+[A-Za-z0-9\-._~+/=]+")]
    private static partial Regex AuthorizationValue();

    /// <summary>key=value or key: value for sensitive keys, as found in query strings, cookies and connection strings.</summary>
    [GeneratedRegex(@"(?i)\b([A-Za-z_\-]*(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|code|cookie|session|otp)[A-Za-z_\-]*)\s*[=:]\s*""?[^&;,\s""]+")]
    private static partial Regex SensitivePair();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")]
    private static partial Regex Jwt();

    /// <summary>A PHC password hash (Argon2 and friends).</summary>
    [GeneratedRegex(@"\$(argon2id|argon2i|argon2d|pbkdf2[A-Za-z0-9-]*|scrypt|bcrypt|2[aby])\$[^\s""',;]+")]
    private static partial Regex PasswordHash();

    /// <summary>
    /// An opaque run of 40+ base64url or hex characters: our refresh, reset and verification tokens are 43, hashes
    /// longer. GUIDs (36 with hyphens in fixed places) and trace ids (32 hex) stay readable.
    /// </summary>
    [GeneratedRegex(@"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_\-])")]
    private static partial Regex LongOpaqueValue();
}

/// <summary>Applies <see cref="LogRedaction"/> to every property of every event, recursively.</summary>
internal sealed class RedactionEnricher : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (KeyValuePair<string, LogEventPropertyValue> property in logEvent.Properties.ToList())
        {
            LogEventPropertyValue redacted = LogRedaction.IsSensitiveName(property.Key) ? new ScalarValue(LogRedaction.Mask) : Redact(property.Value);
            if (!ReferenceEquals(redacted, property.Value))
            {
                logEvent.AddOrUpdateProperty(new LogEventProperty(property.Key, redacted));
            }
        }
    }

    private static LogEventPropertyValue Redact(LogEventPropertyValue value) => value switch
    {
        ScalarValue { Value: string text } => LogRedaction.Redact(text) is string clean && clean != text ? new ScalarValue(clean) : value,
        SequenceValue sequence => new SequenceValue(sequence.Elements.Select(Redact)),
        StructureValue structure => new StructureValue(
            structure.Properties.Select(p => new LogEventProperty(p.Name, LogRedaction.IsSensitiveName(p.Name) ? new ScalarValue(LogRedaction.Mask) : Redact(p.Value))),
            structure.TypeTag),
        DictionaryValue dictionary => new DictionaryValue(dictionary.Elements.Select(e => new KeyValuePair<ScalarValue, LogEventPropertyValue>(
            e.Key,
            e.Key.Value is string key && LogRedaction.IsSensitiveName(key) ? new ScalarValue(LogRedaction.Mask) : Redact(e.Value)))),
        _ => value,
    };
}
