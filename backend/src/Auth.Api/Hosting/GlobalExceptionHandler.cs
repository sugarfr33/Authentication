using Auth.Api.Logging;
using Auth.Services.Passwords;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Auth.Api.Hosting;

/// <summary>
/// Turns any unhandled exception into a generic RFC 9457 ProblemDetails 500. The response never contains the
/// exception message or stack trace, except in the Development environment when <c>Errors:IncludeExceptionDetails</c>
/// is explicitly true (default false). The full exception is logged once, redacted.
/// </summary>
internal sealed partial class GlobalExceptionHandler(
    IProblemDetailsService problemDetails,
    IHostEnvironment environment,
    IConfiguration configuration,
    ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public const string IncludeDetailsKey = "Errors:IncludeExceptionDetails";

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (exception is PasswordHashingBusyException)
        {
            // Overload protection, not a bug: all Argon2 slots are taken. Ask the client to retry shortly.
            LogHashingBusy(logger, httpContext.Request.Method, httpContext.Request.Path.Value ?? string.Empty);
            httpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            httpContext.Response.Headers[HeaderNames.RetryAfter] = "1";
            return await problemDetails.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = httpContext,
                ProblemDetails = new ProblemDetails { Status = StatusCodes.Status503ServiceUnavailable, Title = "The service is busy. Please retry shortly." },
            });
        }

        LogUnhandled(logger, exception.GetType().FullName ?? "Exception", httpContext.Request.Method, httpContext.Request.Path.Value ?? string.Empty, LogRedaction.Redact(exception.ToString()));

        bool includeDetails = environment.IsDevelopment() && configuration.GetValue<bool>(IncludeDetailsKey);
        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;

        ProblemDetails problem = new()
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "An unexpected error occurred.",
            Type = "https://tools.ietf.org/html/rfc9110#section-15.6.1",
            Detail = includeDetails ? exception.GetType().Name + ": " + exception.Message : null,
        };

        return await problemDetails.TryWriteAsync(new ProblemDetailsContext { HttpContext = httpContext, ProblemDetails = problem });
    }

    [LoggerMessage(EventId = 5001, Level = LogLevel.Warning, Message = "Password hashing capacity exhausted on {Method} {Path}; answered 503")]
    private static partial void LogHashingBusy(ILogger logger, string method, string path);

    [LoggerMessage(EventId = 5000, Level = LogLevel.Error, Message = "Unhandled {ExceptionType} on {Method} {Path}: {Error}")]
    private static partial void LogUnhandled(ILogger logger, string exceptionType, string method, string path, string error);
}
