using Auth.Contracts;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Api.Security;

/// <summary>
/// The API's authorization policies. They read only the claims of an access token that AccessTokenCookieHandler has
/// validated (server-signed, live session), so a client cannot add a permission or role to its own request.
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
