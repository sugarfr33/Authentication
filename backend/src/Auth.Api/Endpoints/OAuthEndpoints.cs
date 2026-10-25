using System.Security.Claims;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Accounts;
using Auth.Services.Common;
using Auth.Services.OAuth;
using Auth.Services.Tokens;
using Microsoft.Extensions.Primitives;

namespace Auth.Api.Endpoints;

/// <summary>
/// T19 Authorization Code + PKCE for registered public clients (docs/authorization-code-pkce.md), under /api/v1/oauth.
/// Both endpoints are anonymous by design: /authorize reads the browser session itself, /token is authenticated by the
/// code plus the PKCE verifier (no cookie, so it is exempt from antiforgery; the Origin must be the client's own).
/// Every answer is no-store and no-referrer. Codes appear only in a Location header, never in a body or a log.
/// </summary>
internal sealed class OAuthEndpoints(OAuthOptions options) : IEndpointModule
{
    public const string AuthorizePath = "/api/v1/oauth/authorize";
    public const string TokenPath = "/api/v1/oauth/token";

    private const int MaxQueryLength = 4096;

    private static readonly string[] AuthorizeParameters = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "scope"];
    private static readonly string[] TokenParameters = ["grant_type", "code", "redirect_uri", "client_id", "code_verifier", "refresh_token"];

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder oauth = api.MapGroup("/oauth");

        oauth.MapGet("/authorize", AuthorizeAsync)
            .AllowAnonymous()
            .Produces(StatusCodes.Status302Found)
            .Produces<OAuthErrorResponse>(StatusCodes.Status400BadRequest);

        oauth.MapPost("/token", TokenAsync)
            .AllowAnonymous()
            .Produces<OAuthTokenResponse>()
            .Produces<OAuthErrorResponse>(StatusCodes.Status400BadRequest);
    }

    private async Task<IResult> AuthorizeAsync(HttpContext http, IOAuthService oauth, CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        IQueryCollection query = http.Request.Query;
        if ((http.Request.QueryString.Value?.Length ?? 0) > MaxQueryLength || HasDuplicates(query, AuthorizeParameters))
        {
            return Error(StatusCodes.Status400BadRequest, OAuthErrors.InvalidRequest);
        }

        AuthorizeRequest request = new(
            One(query, "client_id") ?? string.Empty,
            One(query, "redirect_uri") ?? string.Empty,
            One(query, "response_type") ?? string.Empty,
            One(query, "code_challenge") ?? string.Empty,
            One(query, "code_challenge_method") ?? string.Empty,
            One(query, "state"),
            One(query, "scope"));
        AuthorizeOutcome outcome = await oauth.AuthorizeAsync(request, SignedInUser(http.User), AccountEndpoints.AuditFrom(http), cancellationToken);

        switch (outcome.Kind)
        {
            case AuthorizeOutcomeKind.CodeRedirect or AuthorizeOutcomeKind.ErrorRedirect:
                return Results.Redirect(outcome.Location!);
            case AuthorizeOutcomeKind.LoginRequired when options.LoginUrl is Uri login:
                // returnTo is built here from our own fixed path, never taken from the request: always relative.
                string returnTo = AuthorizePath + http.Request.QueryString.Value;
                string separator = string.IsNullOrEmpty(login.Query) ? "?" : "&";
                return Results.Redirect(login.AbsoluteUri + separator + "returnTo=" + Uri.EscapeDataString(returnTo));
            case AuthorizeOutcomeKind.LoginRequired:
                return Error(StatusCodes.Status401Unauthorized, OAuthErrors.LoginRequired);
            default:
                return Error(StatusCodes.Status400BadRequest, outcome.Error ?? OAuthErrors.InvalidRequest);
        }
    }

    private static async Task<IResult> TokenAsync(HttpContext http, IOAuthService oauth, TokenOptions tokenOptions, CancellationToken cancellationToken)
    {
        NoStore(http.Response);
        if (!http.Request.HasFormContentType)
        {
            return Error(StatusCodes.Status415UnsupportedMediaType, OAuthErrors.InvalidRequest);
        }

        IFormCollection form = await http.Request.ReadFormAsync(cancellationToken);
        if (HasDuplicates(form, TokenParameters))
        {
            return Error(StatusCodes.Status400BadRequest, OAuthErrors.InvalidRequest);
        }

        string? clientId = One(form, "client_id");

        // The caller must be the client's own page: its exact registered origin, not just any registered one.
        if (!await oauth.IsClientOriginAsync(clientId, http.Request.Headers.Origin, cancellationToken))
        {
            return Error(StatusCodes.Status400BadRequest, OAuthErrors.InvalidClient);
        }

        AuditContext audit = AccountEndpoints.AuditFrom(http);
        RefreshContext context = new(audit.IpAddress ?? string.Empty, audit.UserAgent ?? string.Empty);
        TokenGrantResult result = One(form, "grant_type") switch
        {
            "authorization_code" => await oauth.ExchangeAsync(
                new TokenExchangeRequest("authorization_code", One(form, "code") ?? string.Empty, One(form, "redirect_uri") ?? string.Empty, clientId!, One(form, "code_verifier") ?? string.Empty),
                context,
                audit,
                cancellationToken),
            "refresh_token" => await oauth.RefreshAsync(One(form, "refresh_token"), clientId, context, audit, cancellationToken),
            null => new TokenGrantResult(null, OAuthErrors.InvalidRequest),
            _ => new TokenGrantResult(null, OAuthErrors.UnsupportedGrantType),
        };

        if (result.Session is not SignedIn session)
        {
            return Error(StatusCodes.Status400BadRequest, result.Error ?? OAuthErrors.InvalidGrant);
        }

        return Results.Json(new OAuthTokenResponse(
            session.AccessToken.Jwt,
            "Bearer",
            (int)tokenOptions.AccessTokenLifetime.TotalSeconds,
            session.RefreshToken.Token));
    }

    /// <summary>The signed-in browser user (a live, server-signed access cookie without client_id), or null.</summary>
    private static Guid? SignedInUser(ClaimsPrincipal user) =>
        user.Identity?.IsAuthenticated == true && Guid.TryParse(user.FindFirst(AuthClaimTypes.Subject)?.Value, out Guid id) ? id : null;

    private static void NoStore(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        response.Headers["Referrer-Policy"] = "no-referrer";
    }

    private static IResult Error(int status, string error) => Results.Json(new OAuthErrorResponse(error), statusCode: status);

    private static bool HasDuplicates(IEnumerable<KeyValuePair<string, StringValues>> values, string[] names) =>
        values.Any(p => p.Value.Count > 1 && names.Contains(p.Key, StringComparer.OrdinalIgnoreCase));

    private static string? One(IQueryCollection values, string name) => values.TryGetValue(name, out StringValues value) && value.Count == 1 ? value[0] : null;

    private static string? One(IFormCollection values, string name) => values.TryGetValue(name, out StringValues value) && value.Count == 1 ? value[0] : null;
}

/// <summary>RFC 6749 error codes used by the OAuth endpoints.</summary>
internal static class OAuthErrors
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnsupportedGrantType = "unsupported_grant_type";
    public const string LoginRequired = "login_required";
}
