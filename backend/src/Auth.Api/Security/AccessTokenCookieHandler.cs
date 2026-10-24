using System.Security.Claims;
using System.Text.Encodings.Web;
using Auth.Contracts;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Security;

/// <summary>
/// Authenticates requests from the access-token cookie only (never an Authorization header), validating the JWT with
/// the token service's parameters, fetched per request from the cached key provider. Failures give a bare 401
/// ProblemDetails that does not say why.
/// </summary>
internal sealed class AccessTokenCookieHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ITokenService tokens,
    ICookieWriter cookies,
    IProblemDetailsService problemDetails) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "AccessTokenCookie";

    /// <summary>A real access token is a few hundred bytes; refuse to parse anything absurdly large.</summary>
    private const int MaxTokenLength = 8192;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(cookies.AccessCookieName, out string? jwt) || string.IsNullOrEmpty(jwt))
        {
            return AuthenticateResult.NoResult();
        }

        if (jwt.Length > MaxTokenLength)
        {
            return AuthenticateResult.Fail("Invalid access token.");
        }

        TokenValidationResult result = await tokens.ValidateAsync(jwt, null, Context.RequestAborted);
        if (!result.IsValid || result.ClaimsIdentity is null)
        {
            return AuthenticateResult.Fail("Invalid access token.");
        }

        return AuthenticateResult.Success(new AuthenticationTicket(PrincipalFrom(result.ClaimsIdentity), Scheme.Name));
    }

    /// <summary>The principal for a validated access token: the same one every later request will authenticate as.</summary>
    internal static ClaimsPrincipal PrincipalFrom(ClaimsIdentity validated) =>
        new(new ClaimsIdentity(validated.Claims, SchemeName, AuthClaimTypes.Name, AuthClaimTypes.Role));

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        WriteProblemAsync(StatusCodes.Status401Unauthorized, "Authentication required.");

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        WriteProblemAsync(StatusCodes.Status403Forbidden, "Access denied.");

    private async Task WriteProblemAsync(int status, string title)
    {
        Response.StatusCode = status;
        await problemDetails.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = Context,
            ProblemDetails = new ProblemDetails { Status = status, Title = title },
        });
    }
}
