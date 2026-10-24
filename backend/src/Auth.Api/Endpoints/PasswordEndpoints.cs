using System.Security.Claims;
using Auth.Api.Security;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Accounts;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Endpoints;

/// <summary>
/// T14 forgot, reset and change password under /api/v1/auth. JSON bodies only; every POST passes the origin check and
/// the antiforgery token, the per-IP limit and the 16 KB cap; forgot-password also the per-account limit.
/// </summary>
internal sealed class PasswordEndpoints : IEndpointModule
{
    /// <summary>The one answer to every well-formed forgot-password request.</summary>
    internal const string ForgotAcceptedMessage = "If an account can reset its password with this address, we sent it an email with a link.";

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder auth = api.MapGroup("/auth");

        auth.MapPost("/forgot-password", ForgotAsync)
            .Accepts<ForgotPasswordRequest>("application/json")
            .Produces<ForgotPasswordResponse>(StatusCodes.Status202Accepted)
            .ProducesValidationProblem();

        auth.MapPost("/reset-password", ResetAsync)
            .Accepts<ResetPasswordRequest>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status400BadRequest);

        auth.MapPost("/change-password", ChangeAsync)
            .RequireAuthorization()
            .Accepts<ChangePasswordRequest>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> ForgotAsync([FromBody] ForgotPasswordRequest request, IPasswordService passwords, HttpContext http, CancellationToken cancellationToken)
    {
        PasswordResult result = await passwords.ForgotPasswordAsync(request, AccountEndpoints.AuditFrom(http), cancellationToken);
        return result.IsSuccess
            ? TypedResults.Accepted((string?)null, new ForgotPasswordResponse(ForgotAcceptedMessage))
            : TypedResults.ValidationProblem(result.ValidationErrors!, title: "The request is invalid.");
    }

    private static async Task<IResult> ResetAsync([FromBody] ResetPasswordRequest request, IPasswordService passwords, HttpContext http, CancellationToken cancellationToken)
    {
        PasswordResult result = await passwords.ResetPasswordAsync(request, AccountEndpoints.AuditFrom(http), cancellationToken);
        return result switch
        {
            { IsSuccess: true } => TypedResults.NoContent(),
            { ValidationErrors: not null } => TypedResults.ValidationProblem(result.ValidationErrors, title: "The new password is not allowed."),
            _ => TypedResults.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The reset link is invalid or has expired."),
        };
    }

    private static async Task<IResult> ChangeAsync(
        [FromBody] ChangePasswordRequest request,
        IPasswordService passwords,
        ICookieWriter cookies,
        IAntiforgery antiforgery,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if ((http.User.Identity as ClaimsIdentity)?.FindFirst(AuthClaimTypes.Subject)?.Value is not string sub || !Guid.TryParse(sub, out Guid userId))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication required.");
        }

        PasswordResult result = await passwords.ChangePasswordAsync(userId, request, AccountEndpoints.AuditFrom(http), cancellationToken);
        if (result.IsSuccess)
        {
            // Every session, this one included, was revoked: the browser signs in again with the new password.
            SessionEndpoints.SignOut(http, cookies, antiforgery);
            return TypedResults.NoContent();
        }

        return result.ValidationErrors is not null
            ? TypedResults.ValidationProblem(result.ValidationErrors, title: "The new password is not allowed.")
            : TypedResults.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The current password is incorrect.");
    }
}
