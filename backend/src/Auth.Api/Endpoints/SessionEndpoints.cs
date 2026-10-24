using System.Security.Claims;
using Auth.Api.Security;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Accounts;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Endpoints;

/// <summary>
/// T13 sign-in and sign-out under /api/v1/auth. Tokens travel only in HttpOnly cookies (ICookieWriter), never in a
/// body. Every POST passes the origin check and the antiforgery token (BrowserProtectionMiddleware); login also passes
/// the per-IP and per-account limits and the 16 KB body cap. Login and both logouts issue a new XSRF token for the new
/// user, because antiforgery tokens are bound to the signed-in user.
/// </summary>
internal sealed class SessionEndpoints : IEndpointModule
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
        Result<SignedIn> result = await signIn.LoginAsync(request, AccountEndpoints.AuditFrom(http), cancellationToken);
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
        HttpContext http,
        CancellationToken cancellationToken)
    {
        // The session to end comes from the signed access token (sid), even if it has just expired: the refresh cookie
        // is scoped to the refresh path and never reaches this endpoint.
        if (http.Request.Cookies.TryGetValue(cookies.AccessCookieName, out string? jwt) && jwt is { Length: > 0 and <= 8192 })
        {
            TokenValidationResult validated = await tokens.ValidateIgnoringLifetimeAsync(jwt, cancellationToken);
            if (validated is { IsValid: true, ClaimsIdentity: not null } && TryGetGuid(validated.ClaimsIdentity, AuthClaimTypes.Subject, out Guid userId))
            {
                Guid? sessionId = TryGetGuid(validated.ClaimsIdentity, AuthClaimTypes.SessionId, out Guid sid) ? sid : null;
                await signIn.LogoutAsync(userId, sessionId, AccountEndpoints.AuditFrom(http), cancellationToken);
            }
        }

        SignOut(http, cookies, antiforgery);
        return TypedResults.NoContent();
    }

    private static async Task<IResult> LogoutAllAsync(
        ISignInService signIn,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (!TryGetGuid(http.User.Identity as ClaimsIdentity, AuthClaimTypes.Subject, out Guid userId))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");
        }

        await signIn.LogoutAllAsync(userId, AccountEndpoints.AuditFrom(http), cancellationToken);
        SignOut(http, cookies, antiforgery);
        return TypedResults.NoContent();
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

    /// <summary>Expires both auth cookies and issues an anonymous XSRF token for the signed-out browser.</summary>
    private static void SignOut(HttpContext http, ICookieWriter cookies, IAntiforgery antiforgery)
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
