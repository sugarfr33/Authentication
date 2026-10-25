using System.Security.Claims;
using Auth.Api.Http;
using Auth.Api.Security;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Accounts;
using Auth.Services.Mfa;
using Auth.Services.Security;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Endpoints;

/// <summary>
/// T21 optional TOTP MFA under /api/v1/auth/mfa (docs/mfa-totp.md). Mapped only when Mfa:Enabled is true, so with the
/// flag off every route here is 404. JSON bodies only; every POST passes the origin check and the antiforgery token
/// (BrowserProtectionMiddleware) and a rate limit. Codes, secrets and the challenge never appear in a log.
/// </summary>
internal sealed partial class MfaEndpoints : IEndpointModule
{
    private const string InvalidFactorTitle = "Invalid or expired verification.";

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder mfa = api.MapGroup("/auth/mfa");

        // Anonymous: the HttpOnly challenge cookie (password already proven) is the credential.
        mfa.MapPost("/verify", VerifyAsync)
            .AllowAnonymous()
            .Accepts<MfaVerifyRequest>("application/json")
            .Produces<UserProfileResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        mfa.MapPost("/enroll", EnrollAsync)
            .RequireAuthorization()
            .Accepts<MfaEnrollRequest>("application/json")
            .Produces<MfaEnrollResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status409Conflict);

        mfa.MapPost("/confirm", ConfirmAsync)
            .RequireAuthorization()
            .Accepts<MfaConfirmRequest>("application/json")
            .Produces<MfaRecoveryCodesResponse>()
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        mfa.MapPost("/recovery-codes", RegenerateAsync)
            .RequireAuthorization()
            .Accepts<MfaFactorsRequest>("application/json")
            .Produces<MfaRecoveryCodesResponse>()
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        mfa.MapPost("/disable", DisableAsync)
            .RequireAuthorization()
            .Accepts<MfaFactorsRequest>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);
    }

    private static async Task<IResult> VerifyAsync(
        [FromBody] MfaVerifyRequest request,
        IMfaService mfa,
        ITokenService tokens,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        string? challenge = http.Request.Cookies.TryGetValue(AuthCookieNames.MfaChallenge, out string? value) ? value : null;
        Result<SignedIn> result = await mfa.VerifyLoginAsync(challenge, request.Code, request.IsRecoveryCode, SessionEndpoints.RefreshCookie(http), HttpAudit.From(http), cancellationToken);
        if (result.Value is not SignedIn session)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: InvalidFactorTitle);
        }

        cookies.ClearMfaChallenge(http.Response);
        await SessionEndpoints.StartBrowserSessionAsync(session, tokens, cookies, antiforgery, http, cancellationToken);
        return TypedResults.Ok(session.Profile);
    }

    private static async Task<IResult> EnrollAsync([FromBody] MfaEnrollRequest request, IMfaService mfa, HttpContext http, CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        if (!TryGetUser(http, out Guid userId))
        {
            return Unauthorized();
        }

        Result<MfaEnrollment> result = await mfa.EnrollAsync(userId, request.Password, HttpAudit.From(http), cancellationToken);
        return result.Value is MfaEnrollment enrollment
            ? TypedResults.Ok(new MfaEnrollResponse(enrollment.OtpAuthUri, enrollment.ManualEntryKey))
            : Failure(result.Error);
    }

    private static async Task<IResult> ConfirmAsync(
        [FromBody] MfaConfirmRequest request,
        IMfaService mfa,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        ILogger<MfaEndpoints> logger,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        if (!TryGetUser(http, out Guid userId))
        {
            return Unauthorized();
        }

        Result<IReadOnlyList<string>> result;
        try
        {
            result = await mfa.ConfirmAsync(userId, request.Code, HttpAudit.From(http), cancellationToken);
        }
        catch (SessionEndFailedException ex)
        {
            // MFA is on and every session is already revoked; only a listener failed. Sign this browser out anyway.
            LogSessionEndFailed(logger, ex.InnerException?.GetType().Name ?? ex.GetType().Name);
            SessionEndpoints.SignOut(http, cookies, antiforgery);
            return TypedResults.Problem(statusCode: StatusCodes.Status500InternalServerError, title: "MFA is on, but ending the other sessions did not complete.");
        }

        if (result.Value is not IReadOnlyList<string> codes)
        {
            return Failure(result.Error);
        }

        // Every session ended (sessions opened with the password alone must not survive): sign this browser out too.
        SessionEndpoints.SignOut(http, cookies, antiforgery);
        return TypedResults.Ok(new MfaRecoveryCodesResponse(codes));
    }

    private static async Task<IResult> RegenerateAsync([FromBody] MfaFactorsRequest request, IMfaService mfa, HttpContext http, CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        if (!TryGetUser(http, out Guid userId))
        {
            return Unauthorized();
        }

        Result<IReadOnlyList<string>> result = await mfa.RegenerateRecoveryCodesAsync(userId, request.Password, request.Code, HttpAudit.From(http), cancellationToken);
        return result.Value is IReadOnlyList<string> codes ? TypedResults.Ok(new MfaRecoveryCodesResponse(codes)) : Failure(result.Error);
    }

    private static async Task<IResult> DisableAsync(
        [FromBody] MfaFactorsRequest request,
        IMfaService mfa,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        ILogger<MfaEndpoints> logger,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        if (!TryGetUser(http, out Guid userId))
        {
            return Unauthorized();
        }

        Result result;
        try
        {
            result = await mfa.DisableAsync(userId, request.Password, request.Code, request.IsRecoveryCode, HttpAudit.From(http), cancellationToken);
        }
        catch (SessionEndFailedException ex)
        {
            LogSessionEndFailed(logger, ex.InnerException?.GetType().Name ?? ex.GetType().Name);
            SessionEndpoints.SignOut(http, cookies, antiforgery);
            return TypedResults.Problem(statusCode: StatusCodes.Status500InternalServerError, title: "MFA is off, but ending the other sessions did not complete.");
        }

        if (!result.IsSuccess)
        {
            return Failure(result.Error);
        }

        SessionEndpoints.SignOut(http, cookies, antiforgery);
        return TypedResults.NoContent();
    }

    private static bool TryGetUser(HttpContext http, out Guid userId)
    {
        userId = Guid.Empty;
        return (http.User.Identity as ClaimsIdentity)?.FindFirst(AuthClaimTypes.Subject)?.Value is string text && Guid.TryParse(text, out userId);
    }

    /// <summary>One answer per kind of failure; never which factor was wrong.</summary>
    private static ProblemHttpResult Failure(AuthError? error) => error switch
    {
        AuthError.ValidationFailed => TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "MFA is not in a state that allows this."),
        AuthError.NotFound => Unauthorized(),
        _ => TypedResults.Problem(statusCode: StatusCodes.Status400BadRequest, title: InvalidFactorTitle),
    };

    private static ProblemHttpResult Unauthorized() =>
        TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");

    private static void NoStore(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
    }

    [LoggerMessage(EventId = 5330, Level = LogLevel.Warning, Message = "An MFA change ended the sessions, but a session-ended listener failed ({ExceptionType})")]
    private static partial void LogSessionEndFailed(ILogger logger, string exceptionType);
}
