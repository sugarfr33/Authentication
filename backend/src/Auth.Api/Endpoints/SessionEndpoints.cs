using System.Security.Claims;
using Auth.Api.Security;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Accounts;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Endpoints;

/// <summary>
/// T13 sign-in and sign-out under /api/v1/auth. Only login and logout read the refresh cookie, and only to END the
/// session it belongs to; no endpoint here refreshes anything. Tokens travel only in HttpOnly cookies (ICookieWriter), never in a
/// body. Every POST passes the origin check and the antiforgery token (BrowserProtectionMiddleware); login also passes
/// the per-IP and per-account limits and the 16 KB body cap. Login and both logouts issue a new XSRF token for the new
/// user, because antiforgery tokens are bound to the signed-in user.
/// </summary>
internal sealed partial class SessionEndpoints : IEndpointModule
{
    /// <summary>The one answer to every failed sign-in, whatever the reason.</summary>
    internal const string InvalidCredentialsTitle = "Invalid email or password.";

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder auth = api.MapGroup("/auth");

        auth.MapPost("/login", LoginAsync)
            .Accepts<LoginRequest>("application/json")
            .Produces<UserProfileResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        // Anonymous on purpose: signing out must work with an expired access token, and always clears the cookies.
        auth.MapPost("/logout", LogoutAsync)
            .Produces(StatusCodes.Status204NoContent);

        auth.MapPost("/logout-all", LogoutAllAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        // Anonymous: the refresh cookie is the credential. Origin check and antiforgery apply like every POST.
        auth.MapPost("/refresh", RefreshAsync)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status409Conflict);

        auth.MapGet("/sessions", ListSessionsAsync)
            .RequireAuthorization()
            .Produces<IReadOnlyList<SessionResponse>>()
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        auth.MapDelete("/sessions/{id}", RevokeSessionAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        auth.MapGet("/me", MeAsync)
            .RequireAuthorization()
            .Produces<UserProfileResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> LoginAsync(
        [FromBody] LoginRequest request,
        ISignInService signIn,
        ITokenService tokens,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        Result<SignedIn> result = await signIn.LoginAsync(request, RefreshCookie(http), AccountEndpoints.AuditFrom(http), cancellationToken);
        if (!result.IsSuccess)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: InvalidCredentialsTitle);
        }

        SignedIn session = result.Value!;
        cookies.WriteAccessToken(http.Response, session.AccessToken);
        cookies.WriteRefreshToken(http.Response, session.RefreshToken);

        // The XSRF token must now be bound to the signed-in user: authenticate as the new token would, then reissue.
        TokenValidationResult minted = await tokens.ValidateAsync(session.AccessToken.Jwt, null, cancellationToken);
        if (minted is { IsValid: true, ClaimsIdentity: not null })
        {
            http.User = AccessTokenCookieHandler.PrincipalFrom(minted.ClaimsIdentity);
            BrowserProtectionMiddleware.IssueTokens(http, antiforgery);
        }

        return TypedResults.Ok(session.Profile);
    }

    private static async Task<IResult> LogoutAsync(
        ISignInService signIn,
        ITokenService tokens,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        ILogger<SessionEndpoints> logger,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        try
        {
            // The session to end comes from either cookie: the sid of the signed access cookie (even if just expired)
            // and the family of the refresh cookie (which outlives the access cookie).
            Guid? userId = null;
            Guid? sessionId = null;
            if (http.Request.Cookies.TryGetValue(cookies.AccessCookieName, out string? jwt) && jwt is { Length: > 0 and <= 8192 })
            {
                TokenValidationResult validated = await tokens.ValidateIgnoringLifetimeAsync(jwt, cancellationToken);
                if (validated is { IsValid: true, ClaimsIdentity: not null } && TryGetGuid(validated.ClaimsIdentity, AuthClaimTypes.Subject, out Guid sub))
                {
                    userId = sub;
                    sessionId = TryGetGuid(validated.ClaimsIdentity, AuthClaimTypes.SessionId, out Guid sid) ? sid : null;
                }
            }

            await signIn.LogoutAsync(userId, sessionId, RefreshCookie(http), AccountEndpoints.AuditFrom(http), cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return SignOutAfterFailure(http, cookies, antiforgery, logger, ex);
        }

        SignOut(http, cookies, antiforgery);
        return TypedResults.NoContent();
    }

    private static async Task<IResult> LogoutAllAsync(
        ISignInService signIn,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        ILogger<SessionEndpoints> logger,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (!TryGetGuid(http.User.Identity as ClaimsIdentity, AuthClaimTypes.Subject, out Guid userId))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");
        }

        try
        {
            await signIn.LogoutAllAsync(userId, AccountEndpoints.AuditFrom(http), cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return SignOutAfterFailure(http, cookies, antiforgery, logger, ex);
        }

        SignOut(http, cookies, antiforgery);
        return TypedResults.NoContent();
    }

    private static async Task<IResult> RefreshAsync(
        ISignInService signIn,
        ITokenService tokens,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        RefreshOutcome outcome = await signIn.RefreshAsync(RefreshCookie(http), AccountEndpoints.AuditFrom(http), cancellationToken);
        switch (outcome.Status)
        {
            case RotationStatus.Rotated when outcome.Session is SignedIn session:
                cookies.WriteAccessToken(http.Response, session.AccessToken);
                cookies.WriteRefreshToken(http.Response, session.RefreshToken);
                await ReissueXsrfForAsync(session.AccessToken, tokens, antiforgery, http, cancellationToken);
                return TypedResults.NoContent();

            case RotationStatus.Concurrent:
                // Another tab refreshed with this token a moment ago; its response carries the new cookies. Change nothing.
                return TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "The session was just refreshed; retry the request.");

            default:
                SignOut(http, cookies, antiforgery);
                return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "The session has ended; sign in again.");
        }
    }

    /// <summary>Maximum sessions listed; a user with more sees the most recently used ones.</summary>
    internal const int MaxListedSessions = 50;

    private static async Task<IResult> ListSessionsAsync(ISignInService signIn, HttpContext http, CancellationToken cancellationToken)
    {
        ClaimsIdentity? identity = http.User.Identity as ClaimsIdentity;
        if (!TryGetGuid(identity, AuthClaimTypes.Subject, out Guid userId))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");
        }

        Guid? current = TryGetGuid(identity, AuthClaimTypes.SessionId, out Guid sid) ? sid : null;
        return TypedResults.Ok(await signIn.ListSessionsAsync(userId, current, MaxListedSessions, cancellationToken));
    }

    private static async Task<IResult> RevokeSessionAsync(
        string id,
        ISignInService signIn,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        ClaimsIdentity? identity = http.User.Identity as ClaimsIdentity;
        if (!TryGetGuid(identity, AuthClaimTypes.Subject, out Guid userId))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");
        }

        // A malformed id, an unknown one and another user's session all get this same 404.
        if (!Guid.TryParse(id, out Guid familyId) || !await signIn.RevokeSessionAsync(userId, familyId, AccountEndpoints.AuditFrom(http), cancellationToken))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status404NotFound, title: "Session not found.");
        }

        if (TryGetGuid(identity, AuthClaimTypes.SessionId, out Guid current) && current == familyId)
        {
            SignOut(http, cookies, antiforgery);
        }

        return TypedResults.NoContent();
    }

    private static async Task ReissueXsrfForAsync(AccessToken access, ITokenService tokens, IAntiforgery antiforgery, HttpContext http, CancellationToken cancellationToken)
    {
        TokenValidationResult minted = await tokens.ValidateAsync(access.Jwt, null, cancellationToken);
        if (minted is { IsValid: true, ClaimsIdentity: not null })
        {
            http.User = AccessTokenCookieHandler.PrincipalFrom(minted.ClaimsIdentity);
            BrowserProtectionMiddleware.IssueTokens(http, antiforgery);
        }
    }

    private static async Task<IResult> MeAsync(ISignInService signIn, HttpContext http, CancellationToken cancellationToken)
    {
        if (TryGetGuid(http.User.Identity as ClaimsIdentity, AuthClaimTypes.Subject, out Guid userId))
        {
            Result<UserProfileResponse> profile = await signIn.GetProfileAsync(userId, cancellationToken);
            if (profile.IsSuccess)
            {
                return TypedResults.Ok(profile.Value);
            }
        }

        return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");
    }

    /// <summary>
    /// The server-side part of a sign-out failed (database error): the browser is still signed out (the answer is built
    /// here, so the exception handler cannot drop the cookie headers), and the 500 tells the caller the session may
    /// still be live on the server. Logged as a warning with the exception type only.
    /// </summary>
    private static ProblemHttpResult SignOutAfterFailure(HttpContext http, ICookieWriter cookies, IAntiforgery antiforgery, ILogger logger, Exception exception)
    {
        LogSignOutFailed(logger, exception.GetType().Name);
        SignOut(http, cookies, antiforgery);
        return TypedResults.Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Signed out in this browser, but the session could not be ended on the server.");
    }

    private static string? RefreshCookie(HttpContext http) =>
        http.Request.Cookies.TryGetValue(AuthCookieNames.Refresh, out string? value) && value is { Length: > 0 } ? value : null;

    [LoggerMessage(EventId = 5300, Level = LogLevel.Warning, Message = "Sign-out could not be completed on the server ({ExceptionType}); the browser cookies were cleared")]
    private static partial void LogSignOutFailed(ILogger logger, string exceptionType);

    /// <summary>Expires both auth cookies and issues an anonymous XSRF token for the signed-out browser.</summary>
    internal static void SignOut(HttpContext http, ICookieWriter cookies, IAntiforgery antiforgery)
    {
        cookies.ClearAuthCookies(http.Response);
        http.User = new ClaimsPrincipal(new ClaimsIdentity());
        BrowserProtectionMiddleware.IssueTokens(http, antiforgery);
    }

    private static bool TryGetGuid(ClaimsIdentity? identity, string claimType, out Guid value)
    {
        value = Guid.Empty;
        return identity?.FindFirst(claimType)?.Value is string text && Guid.TryParse(text, out value);
    }
}
