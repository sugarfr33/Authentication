# Authorization: roles, permissions and policies (T16)

## Model (existing tables, no schema change)

- `auth.Permission` (code, unique) is granted to `auth.Role` through `auth.RolePermission`; users get roles through
  `auth.UserRole`.
- A role is **global** (`ClientApplicationId` null) or **scoped to one client application**. The API's own sessions
  (cookie login) use global roles only. Application roles reach a token only when one is minted for that application
  (OAuth, later task); the repository already filters "global plus this application".
- There is no active/inactive flag on roles or permissions. To "deactivate" one, remove its grants or assignments
  through `IRoleAssignmentService` (below). Adding such a flag would be a schema change to agree first.

## Seeded data

`IAuthorizationSeeder` runs at startup (hosted service `AuthorizationSeedOnStartup`, `Authorization:SeedOnStartup`,
default true) and is **idempotent**: it only adds what is missing and never removes rows, so grants an administrator
adds later are kept (tested). A concurrent seed from a second instance is retried. A failed seed is logged and never
stops the host (without the Admin role nobody holds privileges, so it fails toward fewer rights).

- **Admin always has every permission of `AuthPermissions.All`** (audit LOW-2): a missing Admin grant is added back at
  the next start. Taking a system permission away from Admin is therefore not supported; create a narrower role
  instead.
- **User role backfill** (audit LOW-1): verified, active accounts without the User role (verified while the seed had
  failed or not run) receive it, at most 500 per run (the next run continues), each audited as `RoleAssigned` with
  source `backfill`.

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

**First administrator:** set `Authorization:BootstrapAdminEmail` to the email of an existing verified, active account
and restart; the seeder gives it the Admin role and writes a `RoleAssigned` audit row (source `bootstrap`).
**Remove the setting after first use.**

- The setting only applies while **no active, verified user holds Admin** (the true first-administrator case). Once an
  administrator exists it is ignored, and every start logs a warning asking to remove it; so a configuration value can
  never restore Admin to an account an administrator demoted (tested: demote with another admin present, reseed, no
  re-grant).
- If the email matches no active, verified account, nothing is assigned and a warning is logged.
- **Recovery when no administrator is left** (all deactivated or demoted): set the email of a verified account and
  restart; the rule above makes it apply again (tested). Remove the setting once more afterwards.

## Tokens

The access token minted at login and at every refresh carries `sub` (user id), `sid` (session = refresh family),
`email`, `name`, one `role` claim per role, one `perm` claim per permission (distinct, from the roles), `aud` (the
default audience for cookie sessions) and `iss`. The claims are read from the database **when the token is minted**,
so an added role or grant appears at the next mint (the SPA's next `/refresh`, within one access-token lifetime of 15
minutes). Removals do not wait for that (next section).

## Taking rights away (audit MEDIUM-3)

`IRoleAssignmentService` is the only way to remove rights, and every future admin endpoint must call it:

- `RemoveUserRoleAsync(userId, roleId)`: deletes the assignment and revokes **all refresh families of that user**
  (reason `Admin`), audited as `RoleRemoved`.
- `RemoveRolePermissionAsync(roleId, permissionId)`: deletes the grant and revokes the families of **every user holding
  the role**, audited as `RolePermissionRemoved`.

Each runs in one transaction. The live-session check then rejects the old access tokens: immediately on the instance
that made the change (its cache entries are invalidated), within `SessionLiveness:CacheDuration` (default 5 s, at most
30 s) on the others. The affected users sign in again and get a token with their new rights. Tested at service level
(holders' sessions end, a bystander's survive, nothing changes when the row was not there). A direct database delete
bypasses this and leaves old tokens valid until their next mint (tested: the permission stays until `/refresh`).

## Policies

**Default deny (audit MEDIUM-1):** every endpoint under `/api/v1` requires a signed-in user through a convention on
the route group (`api.RequireAuthorization()` in Program.cs); public endpoints say `.AllowAnonymous()` explicitly
(login, logout, refresh, register, verify-email, forgot-password, reset-password, `/health`, `/health/ready`, JWKS). An
integration test fails if any mapped endpoint has neither authorization metadata nor `AllowAnonymous`, and pins the
exact list of anonymous routes. No `FallbackPolicy`: it also applies to requests that match no endpoint and to routing's
405/415 answers, which would turn a 404 or 415 into 401. `RequireAuthorization()` without a name only means "signed
in": **administration endpoints must name a permission policy**.

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

## Forward notes

- **Administration endpoints (T21b):** see docs/admin-api.md. Each one names a permission policy. Roles are given and
  taken away only through `IRoleAssignmentService` (audited as `RoleAssigned` and `RoleRemoved`), which also refuses
  self-lockout and removing the last active, verified administrator.
- **Privilege ceiling (T21b FIX):** `roles.manage` and `users.write` are not admin-equivalent. A non-administrator
  may give only the roles and permissions they hold themselves, and may not demote, deactivate, reactivate or reset the MFA
  of an Admin holder (docs/admin-api.md, "Privilege ceiling").
- **App-scoped roles (enforced since T18):** `role:Admin` checks the `role` claim. An application role named `Admin`
  can never satisfy it, for two reasons.
  - The API accepts only its default audience, and the registry refuses an application audience equal to it.
  - Application roles are minted only into tokens for that application's audience.
  - Cookie-session tokens carry global roles only.
  - Tested: an app token with an app-scoped Admin role gets 401 on the API. Keep both rules in T19.
- Token size: the access token travels in a cookie (browsers drop cookies over 4096 bytes). A test pins the largest
  realistic token today (every role and permission, near-limit email, 128 non-ASCII display-name characters) under 3500
  bytes; re-check it when application roles add claims.
