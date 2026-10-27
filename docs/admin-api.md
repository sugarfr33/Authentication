# Admin API (T21b)

The HTTP administration surface lives under `/api/v1/admin`. It is a JSON API only; there is no admin UI.
The code is in `Auth.Api/Endpoints/AdminEndpoints.cs`, which calls these services:

- `IUserAdministrationService` and `IAuditQueryService` (both in `Auth.Services/Admin`);
- `IRoleAssignmentService`;
- `IClientApplicationRegistry`.

## Rules for every endpoint

- **Named policy.** Each endpoint requires exactly one permission policy (`perm` claim).
  - A request without a session gets 401 "Authentication required.".
  - A signed-in caller without the permission gets 403 "Access denied.". This is decided before the handler runs, so
    the answer is the same whether or not the id exists. Callers outside admin scope therefore cannot probe which users
    or applications exist.
  - The Admin role holds every permission. A custom role can hold any subset.
- **CSRF and origin.** Every POST, PUT and DELETE needs the usual `Origin` check and the `X-XSRF-TOKEN` header, enforced
  by BrowserProtectionMiddleware.
  - A missing or invalid token gets 400 "Missing or invalid antiforgery token.".
  - A foreign origin gets 403.
- **JSON only.**
  - Bodies must be `application/json`. Any other content type gets 415.
  - Bodies are capped at 16 KB (413) by AccountKeyMiddleware, which now also caps PUT.
- **Rate limit.** Rate-limit kind `Admin` covers the prefix `/api/v1/admin`: 120 requests per minute per IP, for every
  method.
  - The bucket is per client IP, not per administrator: administrators behind one NAT or proxy share it. Raise the
    limit if several administrators work from one address.
  - Configure it under `RateLimiting:Policies:Admin:PerIp`.
  - Over the limit, the answer is 429.
- **No caching.** Every answer carries `Cache-Control: no-store`.
- **No secrets.** Answers never contain any of the following (ResponseDtoTests scans the response types):
  - a password hash;
  - an MFA secret or recovery code;
  - a security stamp, row version or token.
- **Audit rows name the actor.** Every change is audited with `"actor":"<admin user id>"`, taken from the `sub` claim.
- **An actor is required.** A signed-in principal without a usable `sub` (missing, not a GUID, or empty) gets 403
  "Access denied." on every admin endpoint. The services treat a null actor as a trusted host caller (seeding, tests), so
  the admin API never passes one.

## Privilege ceiling

A permission alone does not let its holder make themselves or anyone else more powerful than they are. The checks read
the actor's roles from the database, not from the token.

- **roles.manage without the Admin role:**
  - may assign only a role the actor holds themselves;
  - may grant only a permission the actor holds themselves (through a global role);
  - may not take the Admin role from anyone.
  - So a delegated "role manager" cannot assign Admin to themselves, nor grant `users.write` to a role they hold.
- **users.write without the Admin role:** may not deactivate, reactivate or reset the MFA of an account that holds the
  Admin role.
- An administrator has no ceiling, apart from the guard rails below.

A refusal is 403, with one of these titles:

- "You can only give a role or permission that you hold yourself." (role assignment, permission grant, Admin removal);
- "Only an administrator can change an administrator's account." (deactivate, reactivate, MFA reset).

Nothing is written or audited on a refusal.

## Endpoints

| Method and path | Policy | Answer |
|---|---|---|
| `GET /admin/users?email=&page=&pageSize=` | `users.read` | 200 `AdminUserPage` (see paging below) |
| `GET /admin/users/{id}` | `users.read` | 200 `AdminUserDetail` (account, roles, live session count), 404 |
| `POST /admin/users/{id}/deactivate` | `users.write` | 204, 404, 409 |
| `POST /admin/users/{id}/reactivate` | `users.write` | 204, 404 |
| `POST /admin/users/{id}/mfa/reset` | `users.write` | 204, 404, 409 |
| `GET /admin/roles` | `roles.manage` | 200 roles with their permissions |
| `GET /admin/permissions` | `roles.manage` | 200 permission catalogue |
| `POST /admin/users/{id}/roles` body `{"roleId":"…"}` | `roles.manage` | 204, 404 |
| `DELETE /admin/users/{id}/roles/{roleId}` | `roles.manage` | 204, 409 |
| `POST /admin/roles/{id}/permissions` body `{"permissionId":"…"}` | `roles.manage` | 204, 404 |
| `DELETE /admin/roles/{id}/permissions/{permissionId}` | `roles.manage` | 204, 409 |
| `GET /admin/apps/{appId}/roles` | `roles.manage` | 200 the application's roles with their permissions, 404 |
| `POST /admin/apps/{appId}/roles` body `{"name":"Editor","description":"…"}` | `roles.manage` | 201 `AdminRoleInfo` with `Location`, 400 validation, 404, 409 duplicate name |
| `DELETE /admin/apps/{appId}/roles/{roleId}` | `roles.manage` | 204 (also when already gone), 403 (an administrator holds it and you are not one), 404 (unknown application, or a global or other application's role), 409 (you hold it) |
| `GET /admin/apps` | `apps.manage` | 200 applications |
| `GET /admin/apps/{id}` | `apps.manage` | 200, 404 |
| `POST /admin/apps` body `ClientApplicationRequest` | `apps.manage` | 201 with `Location`, 400 validation |
| `PUT /admin/apps/{id}` body `ClientApplicationRequest` | `apps.manage` | 200, 400, 404 |
| `POST /admin/apps/{id}/activate` | `apps.manage` | 204, 404 |
| `POST /admin/apps/{id}/deactivate` | `apps.manage` | 204, 404 |
| `GET /admin/audit?userId=&eventType=&from=&to=&before=&limit=` | `audit.read` | 200 `AdminAuditPage` (see audit below) |

**Paging the user list.**

- `page` is 1-based, at most 100000.
- `pageSize` is 1 to 100 (default 25).
- `email` is an optional prefix of the normalized email, at most 256 characters.
- Values outside these ranges get 400 ValidationProblem.

**Reading the audit log.**

- Results are newest first.
- `limit` is 1 to 200 (default 50).
- `eventType` must be an `AuditEventType` name.
- `from` and `to` are ISO 8601. A time without an offset is read as UTC.
- To get the next page, pass `nextBefore` as `before`. `nextBefore` is null on the last page.
- Invalid filters get 400.

**Repeated changes.** Repeating a change that has already happened returns 204 and writes no second audit row, because
nothing changed.

A 404 on a POST or DELETE means that either the account, role, permission or application does not exist, or the
assignment being added refers to a missing role. Removing an assignment that does not exist returns 204.

### 409 answers (guard rails)

| Title | When |
|---|---|
| "Administrators cannot make this change to their own account." | The actor deactivates themselves, resets their own MFA, removes one of their own roles, removes a permission from a role they hold, or deletes an application role they hold. |
| "The application already has a role with this name." | Creating an application role whose name another role of that application already has (ignoring case). |
| "At least one active administrator must remain." | The target is the last active, verified holder of the Admin role (removing the role or deactivating the account). |
| "The Admin role always holds every permission." | A permission is removed from the system Admin role. |
| "Two-step verification is not on for this account." | MFA reset on an account with no factor and no pending enrollment. |
| "The account changed at the same time; nothing was changed. Retry." | A deactivation or reset that lost a concurrency race twice. |

The last-administrator check runs inside a transaction that first locks the Admin role row. Two administrators who
demote or deactivate each other at the same moment are therefore serialised: one succeeds and the other is refused, so
an administrator always remains (tested). Depending on timing, the refusal is:

- 409 (last administrator);
- 403 (it is no longer an administrator);
- 401 (its session already ended).

Over HTTP the actor must itself be an administrator (privilege ceiling), so in practice this guard is reached through
such races or by host callers.

Accounts that are inactive or whose email is not verified do not count as administrators. Removing the Admin role from
such a stale account is therefore never refused as "last administrator", because it does not lower the count.

## What each change does

| Change | Effect | Audit row (detail) |
|---|---|---|
| Assign role | Adds the `UserRole`. It takes effect on the user's next sign-in or token refresh. | `RoleAssigned {role, source:"admin", actor}` |
| Remove role | Deletes the `UserRole`, revokes every refresh family, invalidates session liveness and publishes single logout (`AdminRevoked`). The user is signed out everywhere at once. | `RoleRemoved {role, actor}` |
| Grant permission | Adds the `RolePermission`. It takes effect at the holders' next sign-in or refresh. | `RolePermissionGranted {role, permission, actor}` |
| Remove permission | Same as removing a role, for every holder of the role: one call signs out everyone who holds it (a deliberate, audited mass logout). | `RolePermissionRemoved {role, permission, actor}` |
| Deactivate user | Sets `IsActive=false`, issues a new security stamp, revokes every family, invalidates liveness and publishes single logout. Sign-in is refused afterwards. | `UserDeactivated {revoked, actor}` |
| Reactivate user | Sets `IsActive=true` and clears the lockout (failed count, lockout end and level). The user signs in again with their password. | `UserReactivated {actor}` |
| MFA reset | Runs `IMfaService.ResetAsync`: the factor, recovery codes and pending enrollment are removed, a new security stamp is issued and every session ends. | `MfaDisabled {action:"reset", actor}` |
| Create application role (T30) | Adds an empty `Role` with the application's id. Name rules: [authorization.md](authorization.md). | `RoleCreated {role, name, app, clientId, actor}` |
| Delete application role (T30) | Revokes the holders' sessions **at that application only** (their browser and other applications' sessions stay), then deletes the role with its assignments and grants. Refused with 403 when an administrator holds it and the actor is not one. | `RoleDeleted {role, name, app, clientId, revoked, actor}` |
| App create, update, deactivate | Runs through the registry: validation, the CORS origin cache is invalidated, and deactivation revokes the application's sessions. | `AppCreated` / `AppUpdated` / `AppDeactivated` (each with `actor`) |

**Audit reasons.**

- Audit rows, including real failure reasons such as `wrong_password` and `inactive`, are returned only by
  `GET /admin/audit` (`audit.read`).
- No other admin answer contains audit data. A `users.read` holder sees account fields only.

## MFA reset runbook

Use this when a user has lost their authenticator device and every recovery code.

1. **Verify the person first, out of band.** An attacker who already has the password wants exactly this reset. Use the
   identity checks in docs/mfa-admin-recovery.md section 1. Do not accept a request that comes only by email from the
   account's own address.
2. **Find the account.**
   - Use `GET /api/v1/admin/users?email=<prefix>` (users.read).
   - Then check the detail with `GET /api/v1/admin/users/{id}`, where `mfaEnabled` must be true.
3. **Reset.**
   - Send `POST /api/v1/admin/users/{id}/mfa/reset` (users.write) with the antiforgery header.
   - 204 means it is done.
   - 409 "Two-step verification is not on" means there is nothing to reset.
   - You cannot reset your own MFA. Use the disable flow, which asks for your password and a code.
4. **What happens next.**
   - Every session of the user ends at once, in the browser and in every application.
   - Their next sign-in needs only the password. They should enroll again from their profile.
5. **Record it.** The `MfaDisabled` row with `action:"reset"` and your `actor` id is the record. An `audit.read` holder
   can check it with `GET /api/v1/admin/audit?userId={id}&eventType=MfaDisabled`.

The SQL runbook in docs/mfa-admin-recovery.md remains only for when the API is unavailable.

## Changes

- **T30:** application roles over HTTP (`/admin/apps/{appId}/roles`); the existing assignment and grant endpoints work
  for them unchanged. Applications gain `requireRole` (request and response). Omitted, it is false on create and **kept
  unchanged on update** (T30 fix: an older client can never open an application by leaving it out); send `false` to
  turn it off. `AppCreated` and `AppUpdated` audit rows gain `requireRole`. `RoleCreated` and `RoleDeleted` name the
  role and the client id; deleting an application role ends sessions at that application only.

- **T29:** application responses (`ClientApplicationResponse`, `GET/POST/PUT /admin/apps`) no longer have
  `requirePkce`. PKCE was always required and the column is dropped. The list fields are `allowedOrigins`,
  `redirectUris` and `postLogoutRedirectUris`, as before ([client-applications.md](client-applications.md)).

## Tests

`tests/Auth.IntegrationTests/Api/AdminApiTests.cs` covers the following:

- **Policies:** a policy matrix (each endpoint, for each permission holder, answers 403 without its permission) and 401
  without a session.
- **Audit rows:** each one is tested with its exact detail, including the actor.
- **Guard rails:**
  - the last administrator (host caller) and a stale admin account;
  - concurrent mutual demotion and mutual deactivation;
  - the privilege ceiling for a non-admin roles.manage holder, and for a non-admin users.write holder acting on an
    administrator;
  - reactivation clearing the lockout;
  - self-lockout;
  - Admin role permissions.
- **Session effects:**
  - sessions end after a role removal, a permission removal, a deactivation and an MFA reset (for the reset, every
    refresh family is revoked and single logout is published);
  - CORS follows an update that moves the origin, and a deactivation.
- **Request handling:**
  - CSRF, origin, 415, 413 and the rate limit;
  - paging caps and validation;
  - no secrets in answers;
  - audit reasons visible only to `audit.read` holders.
