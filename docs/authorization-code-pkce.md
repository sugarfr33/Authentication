# Authorization Code + PKCE (T19)

Status: **implemented.** Option A was approved by the project lead: the new table `auth.AuthorizationCode`, created
by migration `20261025043218_AuthorizationCodes`, which starts with `SET XACT_ABORT ON`.

Implementation map:

| Part | Where |
|---|---|
| Endpoints | `OAuthEndpoints` (Auth.Api) |
| Authorize, exchange and refresh | `IOAuthService` (Auth.Services/OAuth) |
| App sessions | `IClientSessionService` (`StartAsync` and `RefreshAsync`) |
| Session cap, one refresh pipeline, one claims builder | `ISessionCap`, `ISessionRefresher`, `IAccessProfileBuilder` (Auth.Services/Tokens), shared with browser sessions |
| Per-client origins and redirect URIs | `IClientApplicationOriginProvider.FindActiveAsync` / `MatchOriginAsync` (cached read model) |
| Seams for later clients | `IClientAuthenticator` (public clients: none), `IConsentDecision` (first-party: auto-approve) |
| Error codes | `OAuthErrorCodes` (Auth.Contracts) |
| Code storage | `IAuthorizationCodeRepository` (DAL) |
| Purge | `IRetentionRepository.DeleteEndedAuthorizationCodesAsync` |
| Settings | `OAuth:LoginUrl`, `OAuth:CodeLifetime` (default 60 s, 10 s to 10 min) |

What changed from the design during the build is noted inline (**Built:**). The tests are in `OAuthApiTests`,
`OAuthExchangeTests` (exchange branches with a fake code store) and `RefreshServiceTests`.

## 1. Scope

- **Public clients only.** Registered applications are SPAs on other domains, using PKCE with `S256` only. The schema
  has no client secrets (T18), and none are added.
- **First-party applications only.** The registry is written by administrators (`apps.manage`). There is no
  third-party consent: a signed-in user is **auto-approved** for any active registered application (section 6).
- **Not OpenID Connect.** There is no `id_token` and no UserInfo endpoint. The application learns who the user is
  from the access token claims (`sub`, `email`, `name`).

## 2. Endpoints

Both endpoints are explicitly `AllowAnonymous`: each authenticates in its own way.

### `GET /api/v1/oauth/authorize`

Query parameters:

| Parameter | Rule |
|---|---|
| `client_id` | required |
| `redirect_uri` | required |
| `response_type` | must be `code` |
| `code_challenge` | required: 43 to 128 characters, unreserved alphabet `A-Z a-z 0-9 - . _ ~` |
| `code_challenge_method` | required, `S256` only: `plain` or missing is refused |
| `state` | required: 1 to 512 visible ASCII characters, echoed unchanged |
| `scope` | optional: at most 256 characters of space-separated `[a-z0-9_.:]` tokens. Ignored for authorization: roles and permissions decide (section 5) |

**Validation order**, which is what prevents an open redirect:

1. **Duplicate parameters**, or a query over 4 KB: error page on our domain (400), **never a redirect**.
2. **Unknown or inactive `client_id`, or a `redirect_uri` that is not, character for character (ordinal), one of the
   application's registered redirect URIs:** error page on our domain, **never a redirect**.
   - There is no normalisation before the comparison: case, trailing slash, default port, percent-encoding, user info,
     fragment and scheme all have to match exactly.
   - T18 already refuses fragments, user info and wildcards when registering, and stores the parsed form
     (`Uri.AbsoluteUri`).
3. **Only now** (the redirect URI is trusted), other errors are sent to `redirect_uri` with an RFC 6749 `error` code
   and the `state`:
   - `unsupported_response_type`;
   - `invalid_request` (challenge, method or state missing or bad; scope malformed);
   - `access_denied` (an inactive or unverified user).
4. **No cookie session** (or an expired or ended one): `302` to our login UI, `OAuth:LoginUrl` (configuration, an
   absolute https URL on our domain), with `returnTo=<the original /api/v1/oauth/authorize?... path and query>`.
   - `returnTo` is always a **relative** path built by the server.
   - The login UI must follow it only if it starts with `/api/v1/oauth/authorize?`. That is documented for T23, and
     the server re-validates everything when the browser comes back.
5. **Signed in:** issue a code and `302` to `redirect_uri` with `code` and `state` added to the query (the registered
   URI may already have a query string, which is kept).

Every response from this endpoint carries `Cache-Control: no-store`, `Pragma: no-cache` and
`Referrer-Policy: no-referrer`. The code is in the `Location` header only, never in a body or a log line.

### `POST /api/v1/oauth/token`

The body is `application/x-www-form-urlencoded`, as in RFC 6749. JSON is refused with 415, which keeps one parser and
avoids smuggling between two. The response is JSON with `Cache-Control: no-store`.

- **`grant_type=authorization_code`:** `code`, `redirect_uri`, `client_id`, `code_verifier` (43 to 128 unreserved
  characters).
- **`grant_type=refresh_token`:** `refresh_token`, `client_id` (section 7).

Answers:

| Case | Answer |
|---|---|
| Unknown or inactive client | `400 {"error":"invalid_client"}` |
| Any problem with the code: unknown, expired, used, other client, other redirect URI, wrong verifier | `400 {"error":"invalid_grant"}`, identical every time |
| Missing parameters | `400 {"error":"invalid_request"}` |

The reason goes to the audit log only. Nothing in the error body says which check failed.

### Request protection

- **CORS:** `/token` and the refresh grant are called by the SPA's JavaScript from its own origin. CORS already allows
  only registry origins (T18). The token endpoint additionally requires the request `Origin` to be one of the
  calling `client_id`'s **own** registered origins, not just any registered one.
- **Browser clients only, by design.** Because the Origin must be the client's own, `/token` serves SPAs in a browser.
  A non-browser public client (no `Origin` header) is refused; supporting one would be a deliberate later change.
- **CSRF:** `/token` uses no cookie, so antiforgery is not involved: the code plus the PKCE verifier is the credential.
  The endpoint declares `DisableAntiforgery()` (endpoint metadata, not a path list), and the Origin rule above
  replaces the token check. `/authorize` is a GET with side effects, covered by PKCE (section 6).
- **Rate limits:** kinds `OAuthAuthorize` (per IP) and `OAuthToken` (per IP and per client).
  - **Built:** `OAuthAuthorize` allows 60 per minute per IP.
  - `OAuthToken` allows 30 per minute per IP, and 30 per minute **per client and IP** (`ClientRateLimit`).
  - There is deliberately **no bucket shared by every caller of an application** (T19 recheck M-A). Outside a browser
    `Origin` is just a header, and an application's origin is public, so a shared per-client bucket could be drained
    from many addresses to answer 429 to every real user. Per client and IP, a script with many addresses spends only
    its own buckets; each address stays limited (tested with rotating forwarded addresses). Mass abuse from many
    addresses is a job for the edge (WAF, CDN), not for a per-application budget here.
  - The per-client rule is applied **by the endpoint, after the Origin matched the client's own registered origin**,
    keyed on the canonical client id in lower case (letter-case variants share one bucket) plus the caller's address
    (IPv6 per /64). A request that only names a client from another origin counts against its IP only.
  - An architecture-style test maps the real OAuth routes and checks that every anonymous one has a rate-limit kind.
- **Per-IP limits need the real client IP.** Behind a reverse proxy, `ForwardedHeaders:KnownProxies` must be set (the
  `ProxyMisconfigurationDetector` warns otherwise); without it every user shares the proxy's bucket, and one office
  behind NAT shares one bucket in any case (60 `/authorize` per minute).
- **Built: answers.**
  - Errors are always `{"error": "<code>"}`, never a description of which check failed.
  - Before the redirect URI is trusted: `invalid_client` or `invalid_redirect_uri` (400), or `invalid_request` for
    duplicate parameters or a query over 4 KB.
  - Without a session and without `OAuth:LoginUrl`: `login_required` (401).
- **Built:** a deactivated application's origins leave the CORS and origin lists at once on this instance (within
  the 30 s cache elsewhere). Its `/token` calls are then refused by the general origin check (403) before the exchange
  (tested: never tokens). The client and redirect-URI checks of `/authorize` use the same cached read model; the
  exchange itself re-reads the application from the database.
- **Built: the 30 s cache window for redirect URIs.** On other instances, `/authorize` can keep issuing codes for a
  redirect URI that was just removed (or for an application just deactivated) for up to
  `ClientApplicationOriginOptions.CacheDuration` (30 s); this instance drops the cache at once. Such a code is useless:
  the exchange re-reads the application and requires the code's redirect URI to be **still registered** (reason
  `redirect_mismatch`, T19 recheck L-A, tested), and the application to be active.

## 3. Where codes are stored (decided: table `auth.AuthorizationCode`)

What a code is:

- 256-bit random value (`ITokenGenerator`, base64url, 43 characters);
- **hashed at rest** (SHA-256);
- **60 s** lifetime (`OAuth:CodeLifetime`);
- **single use** through a conditional UPDATE (`UsedUtc IS NULL`, like the one-time-token pattern);
- bound to user, client, exact redirect URI and code challenge.

| Column | Type |
|---|---|
| `Id` | uniqueidentifier, PK, sequential |
| `CodeHash` | binary(32), unique |
| `UserId` | FK to User (cascade) |
| `ClientApplicationId` | FK to ClientApplication (restrict) |
| `RedirectUri` | nvarchar(512) |
| `CodeChallenge` | varchar(128), check 43 to 128 |
| `CreatedUtc`, `ExpiresUtc` | datetime2, check expiry after creation |
| `UsedUtc` | datetime2, null |
| `FamilyId` | uniqueidentifier, null: the session started from the code, written with `UsedUtc` |

Indexes `UQ_AuthorizationCode_CodeHash` and `IX_AuthorizationCode_ExpiresUtc`; foreign keys
`FK_AuthorizationCode_User_UserId` and `FK_AuthorizationCode_ClientApplication_ClientApplicationId`.

- Retention: used or expired codes go with the one-time tokens (7 days after expiry), in bounded batches.
- The alternative without a schema change (a sealed code with the refresh family as the single-use marker) was
  rejected: a second key to manage, and a refresh row that is really a code. A process-memory store was ruled out
  (several instances, restarts).

## 4. Code exchange and binding

On `/token` with `authorization_code` (`OAuthService.ExchangeAsync`), after the endpoint checked the Origin and
the per-client limit:

1. Hash the code and read its row. **Unknown:** `invalid_grant`, counted in the metric `auth.oauth.unknown_codes`
   but **not audited** (such requests carry no user or client, and an audit row each would let anyone grow the audit
   log; T19 audit L2).
2. Choose the family id of the session to come, then open **one transaction** (read committed):
   1. the **burn**, one conditional UPDATE: `UsedUtc = now, FamilyId = @family WHERE Id = @id AND UsedUtc IS NULL`;
   2. the checks, in order, the first failure winning: not expired; the stored `ClientApplicationId` is the requested
      `client_id`'s; the application is active; client authentication (`IClientAuthenticator`: none for public
      clients); `RedirectUri` **ordinal-equal** to the posted one and still in the application's registered list; `BASE64URL(SHA256(ASCII(code_verifier)))` equal to
      the stored challenge (`CryptographicOperations.FixedTimeEquals`);
   3. `IClientSessionService.StartAsync(userId, clientId, family, ...)`: the user must be active and verified, the
      per-user session cap is applied (its `SessionRevoked` rows are **staged** and saved with the new family, in the
      transaction), and the family is created **with that id** (the `IssueAsync` overload taking a family id has one
      caller, checked by an architecture test). It is the only caller of
      `StartAsync` (T18 criterion; an architecture test scans the IL of Auth.Services and Auth.Api for call sites);
   4. commit. A failed check commits the burn alone. An unexpected exception rolls everything back: the code stays
      redeemable until it expires, and nothing half-done remains.
3. **Zero rows** at the burn: a **replay**. The family recorded on the code is revoked (RFC 6819 4.4.1.1), audited
   `AuthorizationCodeRejected` with reason `replayed`, answered `invalid_grant`.

**Built: no replay window.** Because the burn and the family id are one UPDATE and the family is created before the
commit, a replay racing the legitimate exchange blocks on the code row until the commit, then finds the code used and
its family existing, and revokes it (tested with concurrent exchanges, and with a mutation that commits early).
A code redeemed before this fix (used, `FamilyId` null) falls back to revoking the user's families at that application
that started at or after the code was issued.

A failed check does **not** give the code back: it stays used. A failed exchange burns the code, so an attacker cannot
retry verifiers. The failure is audited with its reason and answered with `invalid_grant`.

## 5. The token response

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<opaque>"
}
```

There is no `scope` member: a requested `scope` is validated for syntax and otherwise ignored, because roles and
permissions decide what the token allows.

The access token is the T18 app token:

- `aud` = the application's audience;
- `client_id`;
- `sid` = the application's refresh family;
- global roles plus the application's roles, prefixed `app:{clientId}:{name}`, with their permissions.

It can never reach this API's own endpoints: the default audience is enforced, and the cookie handler rejects any
token with `client_id` (tested in T18). `role:Admin` stays audience-strict.

## 6. Consent, login CSRF and forced authorization

- **Auto-approve:** the registry holds first-party applications only, so a signed-in user is not asked. A consent
  screen, and a `FirstParty` flag to skip it, would be a later schema change.
- **Forced authorization** (an attacker page makes the victim's browser call `/authorize` for a registered
  application):
  - the code is delivered only to that application's registered redirect URI, in the victim's browser;
  - the attacker chose the challenge, so the application's own verifier does not match;
  - the exchange fails, and the code is burned.
- **Login CSRF** (the attacker injects their own code into the victim's application): the application must keep
  `state` and the `code_verifier` in its own tab, in memory or `sessionStorage`, and refuse a callback whose `state`
  it did not create. The injected code also fails PKCE with the victim's verifier. This is documented for T23 as a
  client requirement.
- **What an attacker link can do.** A signed-in victim who opens a link to `/authorize` only ever causes a code to be
  sent to a **registered** redirect URI of a **registered** application. That code is bound to the PKCE challenge in
  the link.
  - If the attacker made the link, the application's own verifier does not match, and the code is useless to
    everyone.
  - If the application started the flow, the attacker never sees the code (it goes to the application in the
    victim's browser) and lacks the verifier anyway.
  - `state` is required and echoed unchanged, so the application can detect a callback it did not start.
  - Beyond what auto-approval of first-party applications implies (a signed-in user is not asked again), `/authorize`
    gives an attacker nothing.
- **Clickjacking:** `/authorize` never renders an approve button, and the API sends `X-Frame-Options: DENY` /
  `frame-ancestors 'none'` (T10).

## 7. Tokens in a cross-domain SPA, and refresh

**Decision:** the access token is kept **in memory only** (a JavaScript variable in a closure or a worker). The refresh
token is returned in the `/token` body and kept **in memory only**: never `localStorage`, `sessionStorage` or a
cookie.

- **Why not a cookie:** our refresh cookie is `__Secure-refresh` on our domain, with `SameSite`. A cross-site SPA's
  fetch to our domain would need third-party cookies, which browsers block. A cookie set on the SPA's own domain would
  need that application's backend, which is out of scope for public clients.
- **Refresh:** `/token` with `grant_type=refresh_token` and `client_id`.
  - The family must belong to that application, the application must be active, and the user must be active.
  - **Built:** it is the same pipeline as the cookie refresh (`ISessionRefresher`): read-only preparation first (a
    failure there, such as signing, leaves the presented token usable), then the rotation with reuse detection, then a
    fresh read of the user (password change, disabled) and of the application, revoking the successor if either
    changed. Rejections are audited `RefreshRejected` with the application id, not as code rejections.
  - Cookie refresh keeps refusing application families (T18), and the app grant refuses browser-session families
    (`ClientApplicationId` null).
- **After a reload** the memory is gone. The SPA starts `/authorize` again with a top-level redirect. Our cookie
  session (still on our domain, first-party in that navigation) is auto-approved, so the user sees a quick bounce, not
  a login form.
- **Threat trade-offs:**
  - Nothing persists, so a theft ends with the tab, and refresh reuse detection kills a stolen family on the next
    legitimate refresh (the XSS trade-off below).
  - Each application's tokens are limited to its own audience and its own `app:` roles.
  - Sessions per user are capped (`RefreshTokens:MaxSessionsPerUser`, 20), counted across browser and application
    sessions alike (`ISessionCap`, used by sign-in and by the code exchange; tested). At the cap, the **same client's**
    least recently used families go first, then the least recently used of the others, so one application (even one
    with injected script) cannot evict the user's browser or other-application sessions while it still has its own
    (T19 recheck L-B, tested). Deactivating the application kills every family (T18).
- **Lifetimes:** access 15 min; refresh sliding 14 days and absolute 30 days, as for browser sessions. A shorter
  absolute cap for application families would be one option in `RefreshTokenOptions`. It is not proposed now.
- **XSS trade-off (accepted, documented):**
  - The in-memory tokens are as exposed as the page: injected script can use them, including the refresh grant, while
    the tab is open. No storage choice in the browser prevents that; only the application's own CSP and output
    encoding do.
  - So keep the access token short: 15 minutes is the default, and shorter is better for applications with a large
    attack surface. Today `TokenOptions.AccessTokenLifetime` is set in code only; binding it from configuration is
    a small follow-up.
  - Never write either token to `localStorage`, `sessionStorage`, IndexedDB or a cookie of the application's
    domain.
- **Built: the reuse grace window.** A refresh token presented again within 10 seconds with the same user agent is
  treated as the losing side of a concurrent refresh (no revocation), as for browser sessions. After that it is reuse:
  the family is revoked (tested).

## 8. Audit and logs

| Event | Detail |
|---|---|
| `AuthorizationCodeIssued` | app id |
| `AuthorizationCodeRedeemed` (the "exchanged" event) | app id, session id |
| `AuthorizationCodeRejected` (appended) | app id when known, and a reason: `unknown_or_expired`, `replayed`, `client_mismatch`, `redirect_mismatch`, `pkce_mismatch`, `inactive_client`, `inactive_user` |

All of these are catalogue-validated, so a code, verifier, challenge, `state` or redirect URI can never be written.
A code that matches no row is not audited: `auth.oauth.unknown_codes` counts it (section 4). The app refresh grant
writes `TokenRefreshed`, `TokenReuse` or `RefreshRejected` (with `app`).

Logs:

- request logging records the path, not the query, so codes and `state` never reach a log line;
- the `Location` header is never logged;
- the T17 redaction masks `code=` pairs and 43-character opaque values anyway, and a test plants codes and verifiers.

## 9. Tests

1. **Full flow:** login, `/authorize`, exchange, the app token's claims, refresh, reuse.
2. **Open-redirect matrix:** unregistered URI, prefix, case, trailing slash, user info, fragment, scheme mismatch,
   encoded variants, duplicate parameters. Every one of them gets our error page and never a `Location` header.
3. **Single use and expiry:** a second exchange is refused, and so is one at 61 s with a fake clock.
4. **PKCE:** wrong verifier, `plain`, a missing method, and a bad challenge length.
5. **Binding:** swap the client, the redirect URI or the user, one at a time.
6. **Replay:** exchange twice, and the family from the first exchange is revoked.
7. **Other:** rate limits on both endpoints; an inactive application; an app token on global endpoints (401); no
   secret in logs or the audit log; Origin of another application on `/token` refused; the refresh grant bound to its
   client.

## 10. Decisions taken

- **Storage:** option A (human approved). The table has check constraints `CK_AuthorizationCode_Expiry` and
  `CK_AuthorizationCode_CodeChallenge_Length` (43 to 128).
- **Lifetimes:** application refresh families keep the browser-session lifetimes (14 days sliding, 30 days absolute).
- **Reserved role names:** global role names must never start with `app:` (`RoleNames.IsReservedForApplications`).
  Any future role-creation code must refuse them, and app tokens drop such global roles defensively.
- **Logs:** the `state` query parameter is masked by the log redaction, like `code` and `code_verifier`.
- **Configuration:** `OAuth:LoginUrl` must be an absolute https URL without user info or fragment (http only for
  localhost in Development); otherwise the app stops at startup.
- **Code lifetime:** `OAuth:CodeLifetime`, validated at startup (10 s to 10 min).

## 11. Not now (noted for later tasks)

- **Session-ended fan-out:** done in T20 (`ISessionEndedPublisher`, single logout and `/oauth/logout`; see
  single-logout-and-shared-domain.md). Back-channel notification of applications is still future work (schema).
- **`iss` in authorization responses (RFC 9207):** protects clients that talk to several authorization servers
  against mix-up. Not needed while each application uses only this server; add it with T22's client library.
- **Confidential clients and consent:** the seams exist (`IClientAuthenticator`, `IConsentDecision`); both are
  no-ops today, and secrets or a consent screen would need a schema change.
