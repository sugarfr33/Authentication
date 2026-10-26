using System.Buffers;
using System.Text.Json;
using Auth.Contracts.Requests;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Runs after the per-IP limiter and before the per-account limiter, on POSTs (and PUTs) to the rate-limited paths.
/// <list type="number">
/// <item><b>Body cap.</b> The body is limited to MaxAccountBodyBytes (16 KB): the server's MaxRequestBodySize is
/// lowered for the request, and the body is read into memory up to that size. Anything larger, chunked or not, gets
/// 413 and never reaches the endpoint. Nothing is buffered to disk.</item>
/// <item><b>Account key</b> (only for kinds with a per-account rule): the email is read exactly like the endpoint's
/// System.Text.Json binder will read it (UTF-8 BOM skipped, depth 64, case-insensitive name, last value wins). A
/// declared non-utf-8 charset gets 415. A body whose email field is ambiguous or unparsable goes to one shared bucket,
/// so parsing tricks cannot escape the per-account limit.</item>
/// </list>
/// </summary>
internal sealed partial class AccountKeyMiddleware(
    RequestDelegate next,
    IOptions<AuthRateLimitOptions> options,
    IProblemDetailsService problemDetails,
    ILogger<AccountKeyMiddleware> logger)
{
    public const string ItemKey = "Auth.RateLimit.Account";

    /// <summary>Shared bucket for bodies whose email field is ambiguous or unparsable.</summary>
    internal const string AmbiguousAccount = "(ambiguous)";

    /// <summary>Same as the System.Text.Json default, so the binder never accepts a body this reader rejects.</summary>
    internal const int BinderMaxDepth = 64;

    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];

    public async Task InvokeAsync(HttpContext context)
    {
        AuthRateLimitOptions settings = options.Value;
        AuthRateLimitKind? kind = settings.Resolve(context.Request.Path);
        // POST and PUT (the admin API updates applications with PUT) get the body cap.
        if (kind is null || !(HttpMethods.IsPost(context.Request.Method) || HttpMethods.IsPut(context.Request.Method)))
        {
            await next(context);
            return;
        }

        int maxBytes = settings.MaxAccountBodyBytes;
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } sizeFeature)
        {
            sizeFeature.MaxRequestBodySize = maxBytes;
        }

        (int failure, byte[]? body) = context.Request.ContentLength > maxBytes
            ? (StatusCodes.Status413PayloadTooLarge, null)
            : await BufferBodyAsync(context, maxBytes);
        if (failure != 0)
        {
            await WriteProblemAsync(context, failure, failure == StatusCodes.Status413PayloadTooLarge ? "Request body too large." : "The request body could not be read.");
            return;
        }

        // The per-client limit of /oauth/token is not keyed here: the endpoint applies it after the Origin check
        // (ClientRateLimit), so an unauthenticated client_id in a body cannot spend another application's budget.
        if (kind != AuthRateLimitKind.OAuthToken && settings.Policies.TryGetValue(kind.Value, out AuthRateLimitPolicy? policy) && policy.PerAccount is not null && context.Request.HasJsonContentType())
        {
            if (!IsUtf8Charset(context.Request.ContentType))
            {
                await WriteProblemAsync(context, StatusCodes.Status415UnsupportedMediaType, "JSON bodies must be UTF-8.");
                return;
            }

            string? account = FindEmail(body);
            if (account is not null)
            {
                context.Items[ItemKey] = account;
            }
        }

        await next(context);
    }

    /// <summary>
    /// Finds the account email the way the endpoint's System.Text.Json web-default binding will see it: a leading UTF-8
    /// BOM is skipped, depth up to 64, property name matched case-insensitively, last occurrence wins. Ambiguous
    /// (duplicated, non-string, blank) or unparsable content (malformed JSON, invalid UTF-8) goes to one shared bucket.
    /// Only an empty body, or a JSON object without the field, gives no account key; the endpoint rejects those anyway.
    /// </summary>
    internal static string? FindEmail(ReadOnlySpan<byte> json)
    {
        if (json.StartsWith(Utf8Bom))
        {
            json = json[Utf8Bom.Length..];
        }

        if (json.Trim(" \t\r\n"u8).IsEmpty)
        {
            return null;
        }

        try
        {
            Utf8JsonReader reader = new(json, new JsonReaderOptions { MaxDepth = BinderMaxDepth });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return AmbiguousAccount;
            }

            int matches = 0;
            bool allStrings = true;
            string? last = null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                bool isEmail = string.Equals(reader.GetString(), AuthRequestFields.Email, StringComparison.OrdinalIgnoreCase);
                if (!reader.Read())
                {
                    return AmbiguousAccount;
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

            string? normalized = EmailNormalizer.Normalize(last);
            return matches > 1 || !allStrings || normalized is null ? AmbiguousAccount : normalized;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            // Malformed JSON, or invalid UTF-8 inside a string (GetString throws InvalidOperationException).
            return AmbiguousAccount;
        }
    }

    internal static bool IsUtf8Charset(string? contentType)
    {
        if (!MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? mediaType) || !mediaType.Charset.HasValue)
        {
            return true;
        }

        string charset = mediaType.Charset.Value!.Trim('"');
        return charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase) || charset.Equals("utf8", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Reads the whole body into memory, at most maxBytes, and rewinds it for the endpoint. Returns failure 0 and the
    /// bytes, or the status to answer: 413 only for a real overflow (counted here, or the server's MaxRequestBodySize),
    /// otherwise the server's own status for a body it could not read (408 timeout / MinRequestBodyDataRate, 400 bad
    /// framing), logged as a warning. A client that disconnected is left to the exception handler (499, no error).
    /// </summary>
    private async Task<(int Failure, byte[]? Body)> BufferBodyAsync(HttpContext context, int maxBytes)
    {
        context.Request.EnableBuffering(bufferThreshold: maxBytes + 1, bufferLimit: maxBytes + 1);
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

            if (total > maxBytes)
            {
                return (StatusCodes.Status413PayloadTooLarge, null);
            }

            context.Request.Body.Position = 0;
            return (0, buffer[..total]);
        }
        catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            return (StatusCodes.Status413PayloadTooLarge, null);
        }
        catch (BadHttpRequestException ex)
        {
            LogUnreadableBody(logger, ex.StatusCode, ex.Message);
            return (ex.StatusCode, null);
        }
        catch (IOException ex) when (!context.RequestAborted.IsCancellationRequested)
        {
            LogUnreadableBody(logger, StatusCodes.Status400BadRequest, ex.Message);
            return (StatusCodes.Status400BadRequest, null);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    [LoggerMessage(EventId = 5110, Level = LogLevel.Warning, Message = "Auth request body could not be read (answered {StatusCode}): {Reason}")]
    private static partial void LogUnreadableBody(ILogger logger, int statusCode, string reason);

    private async Task WriteProblemAsync(HttpContext context, int status, string title)
    {
        context.Response.StatusCode = status;
        await problemDetails.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = new ProblemDetails { Status = status, Title = title },
        });
    }
}
