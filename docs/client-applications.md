# Client applications: registry, CORS source and app tokens (T18)

## Model (existing table, no schema change)

`auth.ClientApplication` has the following columns:

| Column | Meaning |
|---|---|
| `ClientId` | unique |
| `Name` | display name |
| `Audience` | one per application |
| `AllowedOrigin`, `RedirectUri`, `PostLogoutRedirectUri` | JSON arrays |
| `RequirePkce` | always true; only public clients exist |
| `IsActive` | active flag |

There is **no client secret** column: applications are public clients (SPAs, PKCE). Confidential clients with hashed
secrets would need a schema change; ask first.

## Registry service (`IClientApplicationRegistry`, Auth.Services)

| Operation | Behaviour |
|---|---|
| `ListAsync`, `GetAsync` | read, as `ClientApplicationResponse` |
| `CreateAsync(request, active)` | validates, requires an unused client id and audience, audited `AppCreated` (source `registry`) |
| `UpdateAsync(id, request)` | replaces name, audience, origins and redirect URIs; the client id cannot change; audited `AppUpdated` |
| `ActivateAsync(id)` | audited `AppUpdated` with `active: true` |
| `DeactivateAsync(id)` | see "Deactivation" below; audited `AppDeactivated` with the revoked count |
| `BootstrapAsync(options)` | the first application from configuration (below) |

Audit rows hold the application id, flags and counts only, never URLs or names (the catalogue's central redaction).

**No HTTP endpoints yet.** A future admin endpoint must:

- require the `apps.manage` policy (`AuthPolicies.AppsManage`);
- be JSON-only and protected by CSRF, with a rate limit;
- call this service and nothing else.

## Validation (`ClientApplicationValidator`)

Errors name the field only and never echo the submitted value.

- **Client id:** 3 to 100 characters: lower-case letters, digits, `.`, `_` and `-`, starting with a letter or digit.
- **Name:** 1 to 128 characters, no control characters.
- **Audience:**
  - an absolute URI (for example `api://orders`) of at most 256 characters, with no fragment, wildcard or spaces;
  - unique among applications;
  - **never this API's own default audience**, so a token minted for an application can never be accepted by this
    API. That is what keeps an application-scoped role named `Admin` from satisfying `role:Admin` (T16 audit note,
    tested).
- **Allowed origins:**
  - exact `scheme://host[:port]` only, with no path, query, fragment, user info or wildcard;
  - stored normalised (lower case, no trailing slash) and de-duplicated.
- **Redirect and post-logout redirect URIs:**
  - absolute, with no fragment, user info, wildcard or backslash;
  - stored as parsed and matched **exactly** later, never as a prefix or pattern, so there is no open redirect.
  - A query string is allowed (still matched exactly).
- **Scheme:** https only. In Development, plain http is allowed only for loopback hosts (`localhost`, `127.0.0.1`,
  `[::1]`).
- **Caps:** 10 entries per list, 256 characters per origin, 512 per URI.

Tested as a matrix: wildcard, `null`, path, query, fragment, user info, plain http, `javascript:`, relative and
protocol-relative URLs, own audience, caps, and loopback in Development only.

## CORS source

- `IClientApplicationOriginProvider` (singleton) builds the credentialed CORS allow-list from the **active**
  applications' origins, plus `BrowserProtection:TrustedOrigins`.
- Every registry write calls `Invalidate()`, so a change is **immediate on the instance that made it**. A load running
  at the same moment is used once but not cached.
- Other instances see the change within `ClientApplicationOriginOptions.CacheDuration`: **at most 30 s**.
- There is never a wildcard.
- Tested through the real pipeline: a registered origin gets `Access-Control-Allow-Origin`, a look-alike does not, and
  deactivation removes it at once.

## App tokens (`IClientSessionService`)

`StartAsync(userId, clientId, context)` is for the OAuth code exchange (T19); there is no HTTP route to it yet. For an
**active** application and an active, verified user it does three things:

1. Starts a refresh family tied to the application.
2. Mints an access token with these claims:
   - `aud` = the application's audience;
   - `client_id` = its client id;
   - `sid` = the family;
   - the global roles **plus that application's roles**, with their permissions.
3. Returns them.

An unknown or inactive application gets `InvalidClient`. `RefreshTokenService.IssueAsync` also refuses to start a
family for an inactive application (defence in depth). The browser's own cookie session keeps the default audience
and global roles, as before.

## Deactivation

`DeactivateAsync` does the following:

1. In one transaction: sets `IsActive = false` and revokes every refresh token issued to the application (one
   set-based UPDATE, reason `Admin`, like the T16 role-removal pattern).
2. Writes an `AppDeactivated` audit row with the count.
3. Invalidates the session-liveness cache and the CORS cache on this instance.

The live-session check also requires the application of an app family to be active, so its sessions stop at once on
this instance and within `SessionLiveness:CacheDuration` (5 s by default) elsewhere. The application can no longer get
tokens, and refreshing its families fails. Resource APIs that validate app JWTs themselves still see a stateless token
for up to its 15-minute lifetime (threat model, T27).

## Bootstrap (the SPA itself)

`ClientApplications:Bootstrap` (`ClientId`, `Name`, `Audience`, `AllowedOrigins`, `RedirectUris`,
`PostLogoutRedirectUris`) registers one active application at startup (hosted service `ClientApplicationSeedOnStartup`).

- It runs **only while no application exists at all**, like the admin bootstrap. After that it is ignored and logged.
- An invalid configuration registers nothing and logs a warning.
- A failure never stops the host.
- A second instance seeding at the same moment hits the unique client id and backs off.
- Tested against an empty throwaway database: invalid, created, then ignored twice.

## Related

- Cookie session and CORS details: browser-security.md.
- Roles and policies: authorization.md.
- Audit events: audit-and-retention.md.
