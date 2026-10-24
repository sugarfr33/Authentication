using System.Diagnostics;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Accounts;
using Auth.Services.Common;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Endpoints;

/// <summary>
/// T12 self-service sign-up and email verification, under /api/v1/auth. Both are anonymous but, like every POST,
/// pass the origin check and the antiforgery token (BrowserProtectionMiddleware), the per-IP limit, the 16 KB body cap
/// and (register) the per-account limit. Bodies are JSON only.
/// </summary>
internal sealed class AccountEndpoints : IEndpointModule
{
    /// <summary>The one answer to every valid sign-up, new or duplicate email alike.</summary>
    internal const string RegisterAcceptedMessage = "Check your inbox: we sent you an email to finish signing up.";

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder auth = api.MapGroup("/auth");

        auth.MapPost("/register", RegisterAsync)
            .Accepts<RegisterRequest>("application/json")
            .Produces<RegisterResponse>(StatusCodes.Status202Accepted)
            .ProducesValidationProblem();

        auth.MapPost("/verify-email", VerifyEmailAsync)
            .Accepts<VerifyEmailRequest>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest);
    }

    internal static AuditContext AuditFrom(HttpContext http) => new(
        http.Connection.RemoteIpAddress?.ToString(),
        http.Request.Headers.UserAgent.ToString(),
        Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier);

    private static async Task<IResult> RegisterAsync([FromBody] RegisterRequest request, IRegistrationService registration, HttpContext http, CancellationToken cancellationToken)
    {
        RegistrationResult result = await registration.RegisterAsync(request, AuditFrom(http), cancellationToken);
        return result.IsAccepted
            ? TypedResults.Accepted((string?)null, new RegisterResponse(RegisterAcceptedMessage))
            : TypedResults.ValidationProblem(result.ValidationErrors, title: "The registration request is invalid.");
    }

    private static async Task<IResult> VerifyEmailAsync([FromBody] VerifyEmailRequest request, IRegistrationService registration, HttpContext http, CancellationToken cancellationToken)
    {
        Contracts.Result result = await registration.VerifyEmailAsync(request.Token, AuditFrom(http), cancellationToken);
        return result.IsSuccess
            ? TypedResults.NoContent()
            : TypedResults.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The verification link is invalid or has expired.");
    }
}
