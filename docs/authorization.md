# Authorization: roles, permissions and policies (T16)

## Model (existing tables, no schema change)

- `auth.Permission` (code, unique) is granted to `auth.Role` through `auth.RolePermission`; users get roles through
  `auth.UserRole`.
- A role is **global** (`ClientApplicationId` null) or **scoped to one client application**. The API's own sessions
  (cookie login) use global roles only. Application roles reach a token only when one is minted for that application
  (OAuth, later task); the repository already filters "global plus this application".
- There is no active/inactive flag on roles or permissions. To "deactivate" one, remove its grants or assignments;
  the change takes effect at the next token mint (below). Adding such a flag would be a schema change to agree first.

## Seeded data

`IAuthorizationSeeder` runs at startup (hosted service `AuthorizationSeedOnStartup`, `Authorization:SeedOnStartup`,
default true) and is **idempotent**: it only adds what is missing and never removes or changes rows, so grants an
administrator adds later are kept (tested). A concurrent seed from a second instance is retried.

| Permission | Meaning |
|---|---|
| `users.read` | read user accounts |
| `users.write` | create, change, deactivate user accounts |
| `roles.manage` | manage roles, permissions and assignments |
| `sessions.manage` | list and revoke any user's sessions |
| `audit.read` | read the audit log |
| `apps.manage` | register and change client applications |

| Role (global, `IsSystem`) | Permissions |
|---|---|
| `Admin` | all of the above |
| `User` | none; every account gets it when its email is verified |

**First administrator:** set `Authorization:BootstrapAdminEmail` to the email of an existing verified, active account;
the next seeder run gives it the Admin role (once). Remove the setting afterwards.

## Tokens

The access token minted at login and at every refresh carries `sub` (user id), `sid` (session = refresh family),
`email`, `name`, one `role` claim per role, one `perm` claim per permission (distinct, from the roles), `aud` (the
default audience for cookie sessions) and `iss`. The claims are read from the database **when the token is minted**,
so a role or grant change takes effect at the next mint: at the latest after one access-token lifetime (15 minutes),
when the SPA refreshes (tested: removing a role keeps the old token's permission until `/refresh`, then 403).

## Policies

`AuthorizationPolicies.Configure` registers:

- one policy per permission, named after the code (`AuthPolicies.UsersRead == "users.read"`, ...): authenticated and a
  `perm` claim with that exact code;
- `AuthPolicies.AdminRole` (`role:Admin`): authenticated and the `Admin` role.

Use them with `.RequireAuthorization(AuthPolicies.UsersRead)` on an endpoint.

- Not signed in, or the session has ended: **401** ProblemDetails "Authentication required."
- Signed in without the permission or role: **403** ProblemDetails "Access denied." (no policy name or reason in the
  body).

Tested as a matrix through the real pipeline (test-only endpoints, one per policy) for four holders: no role, User,
Admin, and a custom role with only `audit.read`.

**No claim injection:** policies only see claims of an access token that `AccessTokenCookieHandler` validated: signed
by the server's current key with the exact algorithm, right issuer, audience and type, and a live session (live-session
check, see sign-in-and-sessions.md). A token signed by anyone else, even with the same `kid`, is 401 (tested). Claims
never come from headers, the body or a client-readable cookie.

## Not in T16

No administration endpoints exist yet (role assignment, user management); `RoleAssigned`-style audit events arrive
with them.
