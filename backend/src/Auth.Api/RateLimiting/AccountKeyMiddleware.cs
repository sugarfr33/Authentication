using System.Buffers;
using System.Text.Json;
using Auth.Contracts.Requests;
using Microsoft.Extensions.Options;

namespace Auth.Api.RateLimiting;

/// <summary>
/// For a rate-limited POST with a per-account rule, reads at most MaxAccountBodyBytes of the JSON body to find a
/// top-level <c>email</c>, stores the normalized value (trimmed, upper case, like User.NormalizedEmail) for the
/// account partition, and rewinds the body for the endpoint. Larger, chunked-beyond-limit or non-JSON bodies get no
/// account key (they are still IP-limited). Nothing is buffered beyond the limit by this middleware.
/// </summary>
internal sealed class AccountKeyMiddleware(RequestDelegate next, IOptions<AuthRateLimitOptions> options)
{
    public const string ItemKey = "Auth.RateLimit.Account";

    /// <summary>Shared bucket for bodies whose email field is ambiguous (duplicated, non-string or empty).</summary>
    internal const string AmbiguousAccount = "(ambiguous)";

    public async Task InvokeAsync(HttpContext context)
    {
        AuthRateLimitOptions settings = options.Value;
        AuthRateLimitKind? kind = settings.Resolve(context.Request.Path);
        if (kind is not null
            && HttpMethods.IsPost(context.Request.Method)
            && settings.Policies.TryGetValue(kind.Value, out AuthRateLimitPolicy? policy)
            && policy.PerAccount is not null
            && context.Request.HasJsonContentType()
            && (context.Request.ContentLength is null || context.Request.ContentLength <= settings.MaxAccountBodyBytes))
        {
            string? account = await ReadAccountAsync(context, settings.MaxAccountBodyBytes);
            if (account is not null)
            {
                context.Items[ItemKey] = account;
            }
        }

        await next(context);
    }

    private static async Task<string?> ReadAccountAsync(HttpContext context, int maxBytes)
    {
        context.Request.EnableBuffering(bufferThreshold: maxBytes + 1);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(maxBytes + 1);
        try
        {
            int total = 0;
            while (total <= maxBytes)
            {
                int read = await context.Request.Body.ReadAsync(buffer.AsMemory(total, maxBytes + 1 - total), context.RequestAborted);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            context.Request.Body.Position = 0;
            return total > maxBytes ? null : FindEmail(buffer.AsSpan(0, total));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Finds the account email the way the endpoint's System.Text.Json web-default binding will see it: the property
    /// name matches case-insensitively and the last occurrence wins. When the field is ambiguous (present more than
    /// once, not a string, or empty) every such request shares one constant bucket, so ambiguity cannot be used to
    /// dodge the per-account limit. No email field, or malformed JSON, gives no account key (still IP-limited).
    /// </summary>
    internal static string? FindEmail(ReadOnlySpan<byte> json)
    {
        try
        {
            Utf8JsonReader reader = new(json, new JsonReaderOptions { MaxDepth = 8 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            int matches = 0;
            bool allStrings = true;
            string? last = null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                bool isEmail = string.Equals(reader.GetString(), AuthRequestFields.Email, StringComparison.OrdinalIgnoreCase);
                if (!reader.Read())
                {
                    return matches > 0 ? AmbiguousAccount : null;
                }

                if (isEmail)
                {
                    matches++;
                    if (reader.TokenType == JsonTokenType.String)
                    {
                        last = reader.GetString();
                        continue;
                    }

                    allStrings = false;
                }

                reader.Skip();
            }

            if (matches == 0)
            {
                return null;
            }

            string? email = last?.Trim();
            if (matches > 1 || !allStrings || string.IsNullOrEmpty(email) || email.Length > 256)
            {
                return AmbiguousAccount;
            }

            return email.ToUpperInvariant();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
