using System.Globalization;
using System.Security.Claims;
using Auth.Api.Http;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.Services.Admin;
using Auth.Services.Authorization;
using Auth.Services.ClientApplications;
using Auth.Services.Common;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Endpoints;

/// <summary>
/// T21b administration API under /api/v1/admin (docs/admin-api.md).
/// - Every endpoint names one permission policy: users.read, users.write, roles.manage, apps.manage or audit.read. Not
///   signed in: 401; signed in without the permission: 403 "Access denied.", decided before the handler runs, so the
///   answer never depends on whether an id exists.
/// - State changes pass the origin check and the antiforgery token (BrowserProtectionMiddleware) and take JSON bodies
///   only (415 otherwise, 16 KB cap). The whole group has its own per-IP rate limit (kind Admin) and answers no-store.
/// - The acting administrator (the token's sub) goes into the audit context as ActorId: audited as "actor", and used by
///   the services to refuse self-lockout and removing the last active administrator.
/// - Nothing here returns a password hash, MFA secret, recovery code, security stamp or token; audit rows (which can
///   name failure reasons) are returned only by GET /admin/audit.
/// </summary>
internal sealed class AdminEndpoints : IEndpointModule
{
    internal const int DefaultPageSize = 25;
    internal const int MaxPageSize = 100;
    internal const int DefaultAuditLimit = 50;
    internal const int MaxAuditLimit = 200;
    internal const int MaxEmailFilterLength = 256;

    private static readonly HashSet<string> EventTypeNames = new(Enum.GetNames<AuditEventType>(), StringComparer.Ordinal);

    public void Map(IEndpointRouteBuilder api)
    {
        RouteGroupBuilder admin = api.MapGroup("/admin");
        admin.AddEndpointFilter(async (context, next) =>
        {
            context.HttpContext.Response.Headers.CacheControl = "no-store";
            return await next(context);
        });

        // Accounts
        admin.MapGet("/users", ListUsersAsync).RequireAuthorization(AuthPolicies.UsersRead)
            .Produces<AdminUserPage>().ProducesValidationProblem();
        admin.MapGet("/users/{id:guid}", GetUserAsync).RequireAuthorization(AuthPolicies.UsersRead)
            .Produces<AdminUserDetail>().ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapPost("/users/{id:guid}/deactivate", DeactivateUserAsync).RequireAuthorization(AuthPolicies.UsersWrite)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound).ProducesProblem(StatusCodes.Status409Conflict);
        admin.MapPost("/users/{id:guid}/reactivate", ReactivateUserAsync).RequireAuthorization(AuthPolicies.UsersWrite)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapPost("/users/{id:guid}/mfa/reset", ResetMfaAsync).RequireAuthorization(AuthPolicies.UsersWrite)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound).ProducesProblem(StatusCodes.Status409Conflict);

        // Roles, permissions and assignments
        admin.MapGet("/roles", ListRolesAsync).RequireAuthorization(AuthPolicies.RolesManage).Produces<IReadOnlyList<AdminRoleInfo>>();
        admin.MapGet("/permissions", ListPermissionsAsync).RequireAuthorization(AuthPolicies.RolesManage).Produces<IReadOnlyList<AdminPermissionInfo>>();
        admin.MapPost("/users/{id:guid}/roles", AssignRoleAsync).RequireAuthorization(AuthPolicies.RolesManage)
            .Accepts<AdminRoleAssignmentRequest>("application/json")
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapDelete("/users/{id:guid}/roles/{roleId:guid}", RemoveRoleAsync).RequireAuthorization(AuthPolicies.RolesManage)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status409Conflict);
        admin.MapPost("/roles/{id:guid}/permissions", GrantPermissionAsync).RequireAuthorization(AuthPolicies.RolesManage)
            .Accepts<AdminPermissionGrantRequest>("application/json")
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapDelete("/roles/{id:guid}/permissions/{permissionId:guid}", RemovePermissionAsync).RequireAuthorization(AuthPolicies.RolesManage)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status409Conflict);

        // Client applications (the registry: validation, audit, CORS cache invalidation, session revocation)
        admin.MapGet("/apps", ListAppsAsync).RequireAuthorization(AuthPolicies.AppsManage).Produces<IReadOnlyList<ClientApplicationResponse>>();
        admin.MapGet("/apps/{id:guid}", GetAppAsync).RequireAuthorization(AuthPolicies.AppsManage)
            .Produces<ClientApplicationResponse>().ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapPost("/apps", CreateAppAsync).RequireAuthorization(AuthPolicies.AppsManage)
            .Accepts<ClientApplicationRequest>("application/json")
            .Produces<ClientApplicationResponse>(StatusCodes.Status201Created).ProducesValidationProblem();
        admin.MapPut("/apps/{id:guid}", UpdateAppAsync).RequireAuthorization(AuthPolicies.AppsManage)
            .Accepts<ClientApplicationRequest>("application/json")
            .Produces<ClientApplicationResponse>().ProducesValidationProblem().ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapPost("/apps/{id:guid}/activate", ActivateAppAsync).RequireAuthorization(AuthPolicies.AppsManage)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound);
        admin.MapPost("/apps/{id:guid}/deactivate", DeactivateAppAsync).RequireAuthorization(AuthPolicies.AppsManage)
            .Produces(StatusCodes.Status204NoContent).ProducesProblem(StatusCodes.Status404NotFound);

        // Audit log
        admin.MapGet("/audit", QueryAuditAsync).RequireAuthorization(AuthPolicies.AuditRead)
            .Produces<AdminAuditPage>().ProducesValidationProblem();
    }

    private static async Task<IResult> ListUsersAsync(
        string? email,
        int? page,
        int? pageSize,
        IUserAdministrationService service,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string[]> errors = [];
        int pageNumber = page ?? 1;
        int size = pageSize ?? DefaultPageSize;
        if (pageNumber < 1 || pageNumber > 100_000)
        {
            errors["page"] = ["Page must be between 1 and 100000."];
        }

        if (size < 1 || size > MaxPageSize)
        {
            errors["pageSize"] = [string.Create(CultureInfo.InvariantCulture, $"Page size must be between 1 and {MaxPageSize}.")];
        }

        if (email is { Length: > MaxEmailFilterLength })
        {
            errors["email"] = [string.Create(CultureInfo.InvariantCulture, $"The email filter must be at most {MaxEmailFilterLength} characters.")];
        }

        if (errors.Count > 0)
        {
            return TypedResults.ValidationProblem(errors);
        }

        return TypedResults.Ok(await service.ListAsync(email, pageNumber, size, cancellationToken));
    }

    private static async Task<IResult> GetUserAsync(Guid id, IUserAdministrationService service, CancellationToken cancellationToken) =>
        await service.GetAsync(id, cancellationToken) is AdminUserDetail detail ? TypedResults.Ok(detail) : NotFound();

    private static async Task<IResult> DeactivateUserAsync(Guid id, IUserAdministrationService service, HttpContext http, CancellationToken cancellationToken) =>
        Answer(await service.DeactivateAsync(id, ActorAudit(http), cancellationToken));

    private static async Task<IResult> ReactivateUserAsync(Guid id, IUserAdministrationService service, HttpContext http, CancellationToken cancellationToken) =>
        Answer(await service.ReactivateAsync(id, ActorAudit(http), cancellationToken));

    private static async Task<IResult> ResetMfaAsync(Guid id, IUserAdministrationService service, HttpContext http, CancellationToken cancellationToken) =>
        await service.ResetMfaAsync(id, ActorAudit(http), cancellationToken) switch
        {
            AdminOutcome.Unchanged => TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "Two-step verification is not on for this account."),
            AdminOutcome outcome => Answer(outcome),
        };

    private static async Task<IResult> ListRolesAsync(IUserAdministrationService service, CancellationToken cancellationToken) =>
        TypedResults.Ok(await service.ListRolesAsync(cancellationToken));

    private static async Task<IResult> ListPermissionsAsync(IUserAdministrationService service, CancellationToken cancellationToken) =>
        TypedResults.Ok(await service.ListPermissionsAsync(cancellationToken));

    private static async Task<IResult> AssignRoleAsync(
        Guid id,
        [FromBody] AdminRoleAssignmentRequest request,
        IRoleAssignmentService roles,
        HttpContext http,
        CancellationToken cancellationToken) =>
        Answer(await roles.AssignUserRoleAsync(id, request.RoleId, ActorAudit(http), cancellationToken));

    private static async Task<IResult> RemoveRoleAsync(Guid id, Guid roleId, IRoleAssignmentService roles, HttpContext http, CancellationToken cancellationToken) =>
        Answer(await roles.RemoveUserRoleAsync(id, roleId, ActorAudit(http), cancellationToken));

    private static async Task<IResult> GrantPermissionAsync(
        Guid id,
        [FromBody] AdminPermissionGrantRequest request,
        IRoleAssignmentService roles,
        HttpContext http,
        CancellationToken cancellationToken) =>
        Answer(await roles.GrantRolePermissionAsync(id, request.PermissionId, ActorAudit(http), cancellationToken));

    private static async Task<IResult> RemovePermissionAsync(Guid id, Guid permissionId, IRoleAssignmentService roles, HttpContext http, CancellationToken cancellationToken) =>
        Answer(await roles.RemoveRolePermissionAsync(id, permissionId, ActorAudit(http), cancellationToken));

    private static async Task<IResult> ListAppsAsync(IClientApplicationRegistry registry, CancellationToken cancellationToken) =>
        TypedResults.Ok(await registry.ListAsync(cancellationToken));

    private static async Task<IResult> GetAppAsync(Guid id, IClientApplicationRegistry registry, CancellationToken cancellationToken) =>
        await registry.GetAsync(id, cancellationToken) is ClientApplicationResponse application ? TypedResults.Ok(application) : NotFound();

    private static async Task<IResult> CreateAppAsync(
        [FromBody] ClientApplicationRequest request,
        IClientApplicationRegistry registry,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        ClientApplicationResult result = await registry.CreateAsync(request, active: true, ActorAudit(http), cancellationToken);
        return result.Application is ClientApplicationResponse created
            ? TypedResults.Created("/api/v1/admin/apps/" + created.Id.ToString("D"), created)
            : Failure(result);
    }

    private static async Task<IResult> UpdateAppAsync(
        Guid id,
        [FromBody] ClientApplicationRequest request,
        IClientApplicationRegistry registry,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        ClientApplicationResult result = await registry.UpdateAsync(id, request, ActorAudit(http), cancellationToken);
        return result.Application is ClientApplicationResponse updated ? TypedResults.Ok(updated) : Failure(result);
    }

    private static async Task<IResult> ActivateAppAsync(Guid id, IClientApplicationRegistry registry, HttpContext http, CancellationToken cancellationToken) =>
        await registry.ActivateAsync(id, ActorAudit(http), cancellationToken) ? TypedResults.NoContent() : NotFound();

    private static async Task<IResult> DeactivateAppAsync(Guid id, IClientApplicationRegistry registry, HttpContext http, CancellationToken cancellationToken) =>
        await registry.DeactivateAsync(id, ActorAudit(http), cancellationToken) ? TypedResults.NoContent() : NotFound();

    private static async Task<IResult> QueryAuditAsync(
        Guid? userId,
        string? eventType,
        DateTime? from,
        DateTime? to,
        long? before,
        int? limit,
        IAuditQueryService audit,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string[]> errors = [];
        int size = limit ?? DefaultAuditLimit;
        if (size < 1 || size > MaxAuditLimit)
        {
            errors["limit"] = [string.Create(CultureInfo.InvariantCulture, $"Limit must be between 1 and {MaxAuditLimit}.")];
        }

        if (eventType is not null && !EventTypeNames.Contains(eventType))
        {
            errors["eventType"] = ["Unknown event type."];
        }

        if (before is <= 0)
        {
            errors["before"] = ["Before must be a positive row id."];
        }

        DateTime? fromUtc = AsUtc(from);
        DateTime? toUtc = AsUtc(to);
        if (fromUtc is DateTime start && toUtc is DateTime end && start >= end)
        {
            errors["to"] = ["The end must be after the start."];
        }

        if (errors.Count > 0)
        {
            return TypedResults.ValidationProblem(errors);
        }

        return TypedResults.Ok(await audit.QueryAsync(userId, eventType, fromUtc, toUtc, before, size, cancellationToken));
    }

    /// <summary>A time without an offset is read as UTC; one with an offset is converted.</summary>
    private static DateTime? AsUtc(DateTime? value) => value switch
    {
        null => null,
        { Kind: DateTimeKind.Utc } utc => utc,
        { Kind: DateTimeKind.Local } local => local.ToUniversalTime(),
        DateTime unspecified => DateTime.SpecifyKind(unspecified, DateTimeKind.Utc),
    };

    /// <summary>The request's audit context, naming the signed-in administrator as the actor.</summary>
    internal static AuditContext ActorAudit(HttpContext http)
    {
        Guid? actor = (http.User.Identity as ClaimsIdentity)?.FindFirst(AuthClaimTypes.Subject)?.Value is string sub && Guid.TryParse(sub, out Guid id)
            ? id
            : null;
        return HttpAudit.From(http) with { ActorId = actor };
    }

    private static IResult Answer(RoleChangeOutcome outcome) => outcome switch
    {
        RoleChangeOutcome.Changed or RoleChangeOutcome.Unchanged => TypedResults.NoContent(),
        RoleChangeOutcome.NotFound => NotFound(),
        RoleChangeOutcome.SelfLockout => SelfLockout(),
        RoleChangeOutcome.LastAdministrator => LastAdministrator(),
        RoleChangeOutcome.SystemRole => TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "The Admin role always holds every permission."),
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unmapped outcome."),
    };

    private static IResult Answer(AdminOutcome outcome) => outcome switch
    {
        AdminOutcome.Changed or AdminOutcome.Unchanged => TypedResults.NoContent(),
        AdminOutcome.NotFound => NotFound(),
        AdminOutcome.SelfLockout => SelfLockout(),
        AdminOutcome.LastAdministrator => LastAdministrator(),
        AdminOutcome.Conflict => TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "The account changed at the same time; nothing was changed. Retry."),
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unmapped outcome."),
    };

    private static IResult Failure(ClientApplicationResult result) => result.Error == AuthError.NotFound
        ? NotFound()
        : TypedResults.ValidationProblem(result.Errors.ToDictionary(e => e.Key, e => e.Value));

    private static ProblemHttpResult NotFound() => TypedResults.Problem(statusCode: StatusCodes.Status404NotFound, title: "Not found.");

    private static ProblemHttpResult SelfLockout() =>
        TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "Administrators cannot make this change to their own account.");

    private static ProblemHttpResult LastAdministrator() =>
        TypedResults.Problem(statusCode: StatusCodes.Status409Conflict, title: "At least one active administrator must remain.");
}
