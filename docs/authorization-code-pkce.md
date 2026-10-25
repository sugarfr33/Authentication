# Authorization Code + PKCE (T19): design note

Status: **design, before code.** It needs one decision from the project lead: where authorization codes are stored.
The recommended option is an additive table, which is a schema change and needs approval (see section 3).

## 1. Scope

- **Public clients only.** Registered applications are SPAs on other domains, using PKCE with `S256` only. The schema
  has no client secrets (T18), and none are added.
- **First-party applications only.** The registry is written by administrators (`apps.manage`). There is no
  third-party consent: a signed-in user is **auto-approved** for any active registered application (section 6).
- **Not OpenID Connect.** There is no `id_token` and no UserInfo endpoint. The application learns who the user is
  from the access token claims (`sub`, `email`, `name`).

## 2. Endpoints

All three endpoints are explicitly `AllowAnonymous`: each authenticates in its own way.

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
- **CSRF:** `/token` uses no cookie, so antiforgery is not involved: the code plus the PKCE verifier is the credential.
  The path is exempted from the antiforgery check, and the Origin rule above replaces it. `/authorize` is a GET with
  side effects, covered by PKCE (section 6).
- **Rate limits:** new kinds `OAuthAuthorize` (per IP) and `OAuthToken` (per IP and per `client_id`, the "account"
  key for this path).

## 3. Where codes are stored (decision needed)

What a code must be:

- 256-bit random value (`ITokenGenerator`, base64url, 43 characters);
- **hashed at rest** (SHA-256);
- **60 s** lifetime;
- **single use** through a conditional UPDATE (`UsedUtc IS NULL`, like the one-time-token pattern);
- bound to user, client, exact redirect URI and code challenge.

### Option A (recommended): new table `auth.AuthorizationCode`, an additive migration

| Column | Type |
|---|---|
| `Id` | uniqueidentifier, PK, sequential |
| `CodeHash` | binary(32), unique |
| `UserId` | FK to User |
| `ClientApplicationId` | FK to ClientApplication |
| `RedirectUri` | nvarchar(512) |
| `CodeChallenge` | varchar(128) |
| `CreatedUtc`, `ExpiresUtc` | datetime2 |
| `UsedUtc` | datetime2, null |
| `FamilyId` | uniqueidentifier, null: the session started from the code |

Indexes `UQ_AuthorizationCode_CodeHash` and `IX_AuthorizationCode_ExpiresUtc`; foreign keys
`FK_AuthorizationCode_User_UserId` and `FK_AuthorizationCode_ClientApplication_ClientApplicationId`.

- Redemption is one transaction:
  1. a conditional UPDATE marks the code used and returns its row;
  2. the bindings and the verifier are checked;
  3. `IClientSessionService.StartAsync` runs, and `FamilyId` is recorded.
- A **replay** (the conditional UPDATE finds `UsedUtc` already set) revokes the family recorded in `FamilyId`
  (RFC 6819 4.4.1.1) and is audited.
- Retention: used or expired codes go with the one-time tokens (7 days after expiry). The purge gets one more batched
  statement.
- Pros: simple, the same patterns as the reset and verification links, safe on several instances, auditable, tested
  like the rest.
- Cons: a schema change (one table, two indexes, two foreign keys, no change to existing tables).

### Option B (no schema change): sealed code plus the refresh family as the single-use marker

- The code is a 256-bit random value, followed by the binding (user, client, redirect URI, challenge, expiry)
  **encrypted and authenticated** (AES-GCM) with a new server key from `ISecretStore`. That makes it about 200
  characters.
- At `/authorize`, the application's refresh family is created at once. Its first row has
  `TokenHash = SHA-256(code)` and a 60 s expiry, and that row is the single-use marker. The exchange rotates it, so
  the existing reuse detection gives replay revocation for free.
- Cons:
  - a second key to manage and rotate;
  - a refresh token row that is really a code: the refresh grant must be taught never to accept a first-generation
    row, or a stolen code could be refreshed without the verifier;
  - families created for every unexchanged code;
  - harder to explain and review.

**Recommendation: A.** B avoids a migration at the price of a subtler design in the most sensitive flow of the
system.

A process-memory code store is ruled out: it is not safe on several instances, and a restart loses the codes.

## 4. Code exchange and binding

On `/token` with `authorization_code`:

1. Hash the code.
2. Conditional UPDATE: `UsedUtc = now WHERE CodeHash = @h AND UsedUtc IS NULL AND ExpiresUtc > now`.
3. Zero rows: either it is a replay (the code exists and is used: revoke its family and audit
   `AuthorizationCodeRejected` with reason `replayed`), or it is unknown or expired. Both answer `invalid_grant`.
4. Check that the stored `ClientApplicationId` is the requested `client_id`'s, and that the app is still active.
5. Check that the stored `RedirectUri` is **ordinal-equal** to the posted `redirect_uri`.
6. Check `BASE64URL(SHA256(ASCII(code_verifier)))` against the stored challenge with
   `CryptographicOperations.FixedTimeEquals`.
7. Check that the user is still active and verified.
8. Only then call `IClientSessionService.StartAsync(userId, clientId, ...)`: the T18 criterion, this is its only
   caller.

A failed check does **not** give the code back: it stays used. A failed exchange burns the code, so an attacker cannot
retry verifiers. The failure is audited with its reason and answered with `invalid_grant`.

## 5. The token response

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<opaque>",
  "scope": "<as requested>"
}
```

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
  - It uses the existing rotation with reuse detection; reuse revokes the family.
  - Cookie refresh keeps refusing application families (T18), and the app grant refuses browser-session families
    (`ClientApplicationId` null).
- **After a reload** the memory is gone. The SPA starts `/authorize` again with a top-level redirect. Our cookie
  session (still on our domain, first-party in that navigation) is auto-approved, so the user sees a quick bounce, not
  a login form.
- **Threat trade-offs:**
  - XSS in the application can read in-memory tokens while the page is open. That is no worse than any bearer token
    in a SPA. Nothing persists, so the theft ends with the tab, and refresh reuse detection kills a stolen family on
    the next legitimate refresh.
  - Each application's tokens are limited to its own audience and its own `app:` roles.
  - Sessions per user are capped (20), and deactivating the application kills every family (T18).
- **Lifetimes:** access 15 min; refresh sliding 14 days and absolute 30 days, as for browser sessions. A shorter
  absolute cap for application families would be one option in `RefreshTokenOptions`. It is not proposed now.

## 8. Audit and logs

| Event | Detail |
|---|---|
| `AuthorizationCodeIssued` | app id |
| `AuthorizationCodeRedeemed` (the "exchanged" event) | app id, session id |
| `AuthorizationCodeRejected` (appended) | app id when known, and a reason: `unknown_or_expired`, `replayed`, `client_mismatch`, `redirect_mismatch`, `pkce_mismatch`, `inactive_client`, `inactive_user` |

All of these are catalogue-validated, so a code, verifier, challenge, `state` or redirect URI can never be written.

Logs:

- request logging records the path, not the query, so codes and `state` never reach a log line;
- the `Location` header is never logged;
- the T17 redaction masks `code=` pairs and 43-character opaque values anyway, and a test plants codes and verifiers.

## 9. Tests planned

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

## 10. Decision requested

- **Storage:** option A (the new `AuthorizationCode` table, additive migration, recommended) or option B (no schema
  change).
- **Lifetimes:** application refresh families keep the browser-session lifetimes (14 days sliding, 30 days absolute).
