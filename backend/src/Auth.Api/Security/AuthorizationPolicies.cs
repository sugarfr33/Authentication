using Auth.Contracts;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Api.Security;

/// <summary>
/// The API's authorization policies. They read only the claims of an access token that AccessTokenCookieHandler has
/// validated (server-signed, live session), so a client cannot add a permission or role to its own request.
/// Default deny: every endpoint under /api/v1 requires a signed-in user (a convention on the group in Program.cs) and
/// public endpoints say <c>AllowAnonymous()</c> explicitly; an integration test fails if any mapped endpoint has neither.
/// No FallbackPolicy: it would also apply to requests without an endpoint and to the routing 404/405/415 answers,
/// turning them into 401. <c>RequireAuthorization()</c> without a name only means "signed in": administration endpoints
/// must name a permission policy.
/// </summary>
internal static class AuthorizationPolicies
{
    public static void Configure(AuthorizationOptions options)
    {
        // One policy per permission, named after the code: requires a perm claim with exactly that code.
        foreach (string permission in AuthPermissions.All)
        {
            options.AddPolicy(permission, policy => policy.RequireAuthenticatedUser().RequireClaim(AuthClaimTypes.Permission, permission));
        }

        options.AddPolicy(AuthPolicies.AdminRole, policy => policy.RequireAuthenticatedUser().RequireRole(AuthRoles.Admin));
    }
}
