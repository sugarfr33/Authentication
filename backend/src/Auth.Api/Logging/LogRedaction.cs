using System.Globalization;
using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace Auth.Api.Logging;

/// <summary>
/// Redaction policy for every log event: passwords, tokens, cookies, Authorization values, secrets and connection
/// strings never reach a sink. Properties with a sensitive name are replaced outright; every other string value is
/// scrubbed of credential-shaped fragments (Bearer values, key=value pairs, JWTs, password hashes, opaque tokens).
/// </summary>
internal static partial class LogRedaction
{
    public const string Mask = "[REDACTED]";

    /// <summary>Every pattern gives up after this long; a text that takes longer is masked whole (fail closed).</summary>
    private const int MatchTimeoutMilliseconds = 200;

    private static readonly string[] SensitiveNameParts =
    [
        "password", "passwd", "pwd", "secret", "token", "authorization", "cookie", "connectionstring",
        "apikey", "api_key", "api-key", "credential", "privatekey", "private_key", "otp", "recoverycode",
    ];

    public static bool IsSensitiveName(string name) =>
        SensitiveNameParts.Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase));

    public static string Redact(string text)
    {
        try
        {
            string result = AuthorizationValue().Replace(text, "$1 " + Mask);
            result = SensitivePair().Replace(result, "$1=" + Mask);
            result = Jwt().Replace(result, Mask);
            result = PasswordHash().Replace(result, Mask);
            result = LongBase64Value().Replace(result, match => LooksEncoded(match.Value) ? Mask : match.Value);
            result = LongOpaqueValue().Replace(result, Mask);
            return result;
        }
        catch (RegexMatchTimeoutException)
        {
            return Mask;
        }
    }

    [GeneratedRegex(@"(?i)\b(bearer|basic|negotiate)\s+[A-Za-z0-9\-._~+/=]+", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex AuthorizationValue();

    /// <summary>
    /// key=value or key: value, as found in query strings, cookies and connection strings, where the key is exactly
    /// code, code_verifier or state (OAuth query strings), or ends with password, passwd, pwd, secret, token, apikey, cookie or otp (so newPassword,
    /// refresh_token, Cookie). Keys that only contain such a word (StatusCode, SessionId, TokenType) stay readable.
    /// </summary>
    [GeneratedRegex(@"(?i)(?<![A-Za-z0-9_\-])(code|code_verifier|state|[A-Za-z_\-]*(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|cookie|otp))\s*[=:]\s*""?[^&;,\s""]+", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex SensitivePair();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex Jwt();

    /// <summary>
    /// A PHC password hash (Argon2 and friends), from the algorithm marker to whitespace, a quote or a semicolon: the
    /// parameters contain commas (m=65536,t=3,p=1), so a comma never ends the match (T17 Tester F1).
    /// </summary>
    [GeneratedRegex(@"\$(argon2id|argon2i|argon2d|pbkdf2[A-Za-z0-9-]*|scrypt|bcrypt|2[aby])\$[^\s""';]+", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex PasswordHash();

    /// <summary>
    /// An opaque run of 43+ base64url or hex characters: our refresh, reset and verification tokens are exactly 43,
    /// hashes longer. GUIDs (36), trace ids (32) and ordinary long identifiers stay readable.
    /// </summary>
    [GeneratedRegex(@"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43,}(?![A-Za-z0-9_\-])", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex LongOpaqueValue();

    /// <summary>
    /// A run of 43+ standard base64 characters (with + or /, optional = padding). It is masked only when it looks
    /// encoded (upper case, lower case and digits all present), so URL paths such as /api/v1/auth/forgot-password stay
    /// readable (T17 Tester F1).
    /// </summary>
    [GeneratedRegex(@"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/]{43,}={0,2}(?![A-Za-z0-9_\-+/=])", RegexOptions.None, MatchTimeoutMilliseconds)]
    private static partial Regex LongBase64Value();

    /// <summary>Upper and lower case, plus a digit unless the value already has a + or / (T18 audit L7).</summary>
    private static bool LooksEncoded(string value) =>
        value.Any(char.IsAsciiLetterUpper) && value.Any(char.IsAsciiLetterLower)
        && (value.Any(char.IsAsciiDigit) || value.Contains('+', StringComparison.Ordinal) || value.Contains('/', StringComparison.Ordinal));
}

/// <summary>Applies <see cref="LogRedaction"/> to every property of every event, recursively.</summary>
internal sealed class RedactionEnricher : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (KeyValuePair<string, LogEventPropertyValue> property in logEvent.Properties.ToList())
        {
            LogEventPropertyValue redacted;
            try
            {
                redacted = LogRedaction.IsSensitiveName(property.Key) ? new ScalarValue(LogRedaction.Mask) : Redact(property.Value);
            }
            catch (Exception)
            {
                // Fail closed (T18 audit L7): a value whose ToString throws, or any other surprise, is masked.
                redacted = new ScalarValue(LogRedaction.Mask);
            }

            if (!ReferenceEquals(redacted, property.Value))
            {
                logEvent.AddOrUpdateProperty(new LogEventProperty(property.Key, redacted));
            }
        }
    }

    private static LogEventPropertyValue Redact(LogEventPropertyValue value) => value switch
    {
        ScalarValue { Value: string text } => LogRedaction.Redact(text) is string clean && clean != text ? new ScalarValue(clean) : value,
        ScalarValue { Value: object other } when !IsPlainValue(other) => RedactRendered(value, other),
        SequenceValue sequence => new SequenceValue(sequence.Elements.Select(Redact)),
        StructureValue structure => new StructureValue(
            structure.Properties.Select(p => new LogEventProperty(p.Name, LogRedaction.IsSensitiveName(p.Name) ? new ScalarValue(LogRedaction.Mask) : Redact(p.Value))),
            structure.TypeTag),
        DictionaryValue dictionary => new DictionaryValue(dictionary.Elements.Select(e => new KeyValuePair<ScalarValue, LogEventPropertyValue>(
            e.Key,
            e.Key.Value is string key && LogRedaction.IsSensitiveName(key) ? new ScalarValue(LogRedaction.Mask) : Redact(e.Value)))),
        _ => value,
    };

    /// <summary>
    /// A scalar that is not a plain value (a Uri with a token in its query, any type whose ToString carries text) is
    /// rendered and scrubbed; when something was masked it becomes the scrubbed string.
    /// </summary>
    private static LogEventPropertyValue RedactRendered(LogEventPropertyValue original, object value)
    {
        string text = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
        string clean = LogRedaction.Redact(text);
        return clean == text ? original : new ScalarValue(clean);
    }

    private static bool IsPlainValue(object value) =>
        value is bool or char or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal
            or DateTime or DateTimeOffset or TimeSpan or Guid or Enum;
}
