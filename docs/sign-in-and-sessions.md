# Sign-in, sign-out and the profile (T13)

All under `/api/v1/auth`. Tokens travel **only** in HttpOnly, Secure cookies (`__Host-access`, path `/`;
`__Secure-refresh`, path `/api/v1/auth`); no response body, URL or readable header ever carries one. Every POST needs
an allowed Origin and the `X-XSRF-TOKEN` header (browser-security.md).

The refresh cookie path is `/api/v1/auth` (still `__Secure-`, HttpOnly, Secure, SameSite=Strict) so that logout and
login can end the session it belongs to. Only `/refresh` rotates it; `/login` and `/logout` only read it to **revoke**
its family; every other route ignores it (tested: with only the refresh cookie, `/me` is 401 and sets no cookie).

| Endpoint | Auth | Body | Success | Failure |
|---|---|---|---|---|
| `POST /login` | anonymous | `{ "email", "password" }` (JSON only) | **200** `UserProfileResponse`, both cookies set, new XSRF-TOKEN | **401** ProblemDetails "Invalid email or password." |
| `POST /logout` | anonymous (works with an expired access cookie) | none | **204**, both cookies expired, new anonymous XSRF-TOKEN | - |
| `POST /logout-all` | signed in | none | **204**, every session revoked, cookies expired, new XSRF-TOKEN | **401** |
| `GET /me` | signed in | - | **200** `UserProfileResponse` | **401** (also for an inactive or deleted account) |
| `POST /refresh` (T15) | refresh cookie | none | **204**, both cookies rotated, XSRF reissued for the user | **401** (cookies expired) for an unknown, expired, revoked or reused token; **409** for the losing side of a concurrent refresh (cookies untouched) |
| `GET /sessions` (T15) | signed in | - | **200** array of `SessionResponse` | **401** |
| `DELETE /sessions/{id}` (T15) | signed in | none | **204** (current session: cookies expired too) | **404** "Session not found." for a malformed, unknown or another user's id; **401** |

`UserProfileResponse`: id, email, emailVerified, displayName, mfaEnabled, roles, permissions. No hash, stamp, lockout
counters or secrets.

## Login

1. The email is normalized with the shared `EmailNormalizer` and looked up (a blank or over-long email looks up nothing).
2. The account can sign in only if it exists, is active, has a verified email, has a password (not the empty
   "no usable password" of an unverified registration), is not locked, and has no MFA (the MFA step comes with a later
   task; until then an MFA account is refused generically).
3. `IAuthTimingGuard.CheckPasswordAsync` always does **exactly one Argon2 Verify**: against the stored hash for a usable
   account, against the startup-made dummy hash otherwise. The raw length cap (1024) and the 128 code-point cap apply
   before any Verify, whatever the account. Only `VerifyAsync`/`HashAsync` go through the bounded hashing gate (busy =
   503 with Retry-After).
4. **Failure** (any reason): `ILockoutService.RegisterFailureAsync` (for an unknown email it looks up an id that
   cannot exist, so every path does a lockout round trip), then a `LoginFailed` audit row (reason `unknown`,
   `wrong_password`, `unverified`, `inactive`, `locked`, `no_password` or `mfa_not_supported`; plus a `Lockout` row when
   this failure locked the account). The answer is always the same 401 body (apart from `traceId`), with no cookies
   (tested for nine different causes).
5. **Success:** the lockout counter is reset; last login (and a rehash when the parameters changed) is saved together
   with the `LoginSucceeded` audit row and the new refresh family (IP and user agent recorded on it); an access token
   is minted for the **default audience** with `sid` = the family id. Then both cookies are written and the XSRF token
   is reissued for the new user (antiforgery tokens are user-bound).

Audit rows are staged only **after** `RegisterFailureAsync`/`ResetAsync`, because their concurrency retry clears the
change tracker (the same rule as for `RotateAsync`).

`LoginRequest.ClientId` is accepted but **ignored** until the OAuth authorization-code flow (T15+): refresh families are
created with no client application and the access token is for the default audience.

**Re-login replaces the old session:** if the browser presents a refresh cookie when signing in successfully, that
family is revoked (reason Logout, only for its own user) before the new one is created, so no orphan session is left
alive (tested).

### Residual timing difference

A failure for an existing account writes the lockout UPDATE as well as the audit INSERT; an unknown email does a
lookup and the INSERT only. That is one extra small statement (well under a millisecond on the same host) next to
about 100 ms of Argon2. Locked accounts do no UPDATE either (failures while locked are not counted).

## Logout

The session to end is found from **either** cookie:

- the **refresh cookie** (it outlives the access cookie): its hash is looked up and its family revoked, so logout works
  after the 15-minute access cookie has expired and been dropped (tested);
- the **signed access cookie**: `sub` and `sid` are read after a full signature, issuer, audience and type check, with
  only the lifetime check skipped (`ITokenService.ValidateIgnoringLifetimeAsync`, used for nothing else), so an expired
  access cookie alone still works (tested with a backdated, correctly signed token).

Families are revoked with `RevokeFamilyForUserAsync(familyId, userId)` (reason `Logout`): a token can end only a
family of its own user (tested with a forged sid of another user). A `Logout` audit row is written; its user id is
left empty when the account no longer exists (AuditLog has a foreign key to User), so a deleted account's browser still
signs out with 204 (tested).

Both logouts **always** clear the cookies: if the server-side part fails (database error) the cookies are still
expired, the XSRF token reissued, a warning logged (exception type only) and the answer is a 500 ProblemDetails saying
the session may still be live on the server.

**Single logout (T20):** ending a browser session (logout, logout-all, revoking a browser session, a detected
refresh-token theft, a password change) also ends every application session of the user. See
single-logout-and-shared-domain.md.

**MFA (T21):** with `Mfa:Enabled`, a correct password for an account with MFA answers `202 {"mfa_required": true}`
and sets the `__Secure-mfa` challenge cookie instead of starting a session. The session starts at
`POST /auth/mfa/verify` (docs/mfa-totp.md). With the flag off, such accounts fail closed, getting the generic 401.

## Logout-all

Needs a valid access cookie. Revokes every refresh family of the user (reason `LogoutAll`, one UPDATE), writes a
`LogoutAll` audit row with the count, expires the cookies and reissues an anonymous XSRF token. Access tokens already
issued elsewhere stop working within the live-session cache time (see "Live-session check" below).

## Refresh (T15)

`POST /refresh` rotates the refresh cookie with the T08 rules (`IRefreshTokenService.RotateAsync`: one winner of a
race, a replayed token revokes its whole family) and mints a new access token for the default audience with the same
`sid`. Like every POST it needs an allowed Origin and the antiforgery token. It runs in three steps (T15 audit fix):

1. **Read-only preparation, before anything changes:** find the session of the cookie, refuse a client-application
   family (it keeps its own audience and is refreshed by the OAuth flow, never converted to the default audience),
   load the user (inactive or unverified: the family is revoked, 401), build the profile and **mint the access token**.
   A failure here (database, signing) leaves the presented token untouched, so the client can just retry.
2. **The rotation** (its own transaction).
3. **After the commit:** the user is read again (not the tracked copy). If the SecurityStamp changed (a password change
   raced the rotation) or the account was disabled meanwhile, or any step fails, the new family is revoked and the
   answer is a clean 401 with `RefreshRejected` audited: no orphaned successor stays live, and the client never gets a
   500 that loses its new token. The `TokenRefreshed` audit row is best effort (a failure is logged as a warning and does
   not change the answer).

Audit precision: `TokenReuse` only when a replay actually revoked a live family (a theft signal). A replayed token of
a session that had already ended (logout, logout-all, password change, revoked session) is `RefreshRejected`
(`ended_session_replayed`), not reuse. Refused refreshes are counted and logged as one warning at most once a minute
(no values), so cookie guessing is visible beyond the 429s.

**SPA flow (T23):** antiforgery tokens are bound to the user. When the access cookie has expired the browser is
anonymous again, so the XSRF pair it holds (issued while signed in) no longer fits and `POST /refresh` answers **400**
(tested). The SPA must first do a GET under `/api` (the 401 from `/me` is enough) to get an anonymous pair, then refresh;
or retry once after a 400. After a successful refresh the pair is reissued for the user. Refresh calls should also be
serialised across tabs: two tabs refreshing outside the 10 s grace window look like reuse and end the session.

## Active sessions (T15)

`GET /sessions` lists the caller's **own** live sessions: one row per refresh family (not per token) that still has
a token that is neither revoked nor expired, most recently used first, at most 50.

| Field | Meaning |
|---|---|
| `familyId` | opaque session id (the refresh family id; also the access token `sid`) |
| `createdUtc` | when the session started: the earliest token of the family (the T08 anchor of the 30-day cap) |
| `lastUsedUtc` | when it was last refreshed (its live token) |
| `ip`, `userAgent` | of the last refresh; for display, control and invisible characters and `<` `>` `&` `"` `'` are removed and they are capped at 45 and 256 characters (stored values unchanged). The UI must still render them as **text**, never as HTML |
| `isCurrent` | true for the family named by the caller's own `sid` |

No token, hash, SecurityStamp, row id or user id is returned (tested). The DAL returns a read model
(`IRefreshSessionSummary`), never an entity.

`DELETE /sessions/{id}` revokes one of the caller's sessions (`RevokeFamilyForUserAsync`, reason `Logout`, audit
`SessionRevoked` with the session id). Another user's session id, an unknown id and a malformed id all give the
**identical 404** (tested), so ids of other users cannot be probed. Revoking an already revoked own session is **204**
again (idempotent; audited only when something was revoked). Revoking the current session also expires this browser's
cookies, like logout. A revoked session cannot refresh (tested through `/refresh`: 401).

## Deferred (notes from the T15 review and audit)

- **Cap on live sessions per user (done in T17).** `RefreshTokens:MaxSessionsPerUser` (default 20, 1 to 1000; the
  `RefreshTokens` section is bound and validated at startup).
  Before a login, or an OAuth code exchange (T19), issues a new family, the least recently used live families beyond
  19 are revoked, counting browser and application sessions together (`ISessionCap`; the starting client's own
  families, or the browser's for a login, go first) (reason `Admin`,
  audited `SessionRevoked` with reason `session_cap`, cache invalidated on this instance). Done before the new session
  exists, so a failure fails the login cleanly. Two simultaneous logins can leave one family over the cap until the
  next login (tested: the 4th login with a cap of 3 ends the oldest; the list shows the 3 newest).
  - The revoked reason stays `Admin`: `RefreshToken.RevokedReason` has a CHECK constraint, so a dedicated value would be
    a schema change. The audit row carries `session_cap`.
  - Someone who knows the password can evict the owner's sessions by logging in 20 times (rate limited). The owner
    only sees `SessionRevoked` rows. Follow-up: a "new sign-in" email to the owner (not built).
- **Audit volume (decided in T17).** `TokenRefreshed` is kept (no sampling) but is high-volume: it gets the short audit
  retention (default 90 days), see audit-and-retention.md.
- **Sessions limiter is per IP** (60 per minute), not per user.
- **Cross-tab refresh** (T23): serialise refresh in the SPA (see above).

## Live-session check (T16 prerequisite)

A signed, unexpired access cookie is not enough: after the signature check, `AccessTokenCookieHandler` asks
`ISessionLiveness` whether the token's `sid` family still has a token that is neither revoked nor expired and whether the
user (`sub`) is still active. That is one indexed query (`IsSessionLiveAsync`), cached per family for
`SessionLiveness:CacheDuration` (default **5 s**, 0 to 30; 0 disables the cache) and bounded by
`SessionLiveness:MaxEntries` (10 000). A cached entry is only reused for the same user.

- **Per instance.** Each API instance has its own cache. `/logout`, `/logout-all`, `DELETE /sessions/{id}` and role
  removals (`IRoleAssignmentService`) invalidate the entries on the instance that handled them, so there the change is
  immediate; other instances see it when their entry expires (at most `CacheDuration`, never more than 30 s).
- **Bounded, no stampede (audit LOW-4).** The entry count is an Interlocked counter (no `ConcurrentDictionary.Count` per
  miss). When full, expired entries are evicted first and the cache is emptied only if that is not enough. Concurrent
  misses for the same session share one lookup; a caller whose request is aborted stops waiting without failing the
  others. A lookup that overlaps an invalidation does not cache its answer.
- **Failures are not cached (audit LOW-5, accepted).** During a database outage every authenticated request retries
  the lookup and gets 401. A short negative cache was considered and not added: failing closed matters more than
  sparing a sick database, and the connection pool already bounds the load.

- Not live (revoked, expired, unknown family, inactive user) or **no `sid` claim**: the request is unauthenticated (401
  on protected routes). Every way a password changes (change, reset) also revokes every family, so a SecurityStamp
  check would add nothing: the `sid` check covers it.
- **Fails closed:** if the lookup throws, the request is unauthenticated and the 401 body is the usual bare one
  (tested). The failure is logged as one warning per minute at most (`LivenessFailureLog`: count since the last report
  and the latest exception type only), so an outage does not log one line per request (tested).
- `/logout`, `/refresh` and the login flow are anonymous and handle ended sessions themselves. Because antiforgery
  tokens are user-bound, a browser whose session was ended elsewhere is anonymous again and must fetch an anonymous XSRF
  pair (any GET under /api) before its next POST, the same SPA flow as after access-cookie expiry.
- Tested: logout-all, revoking a session, a password change and deactivation each make another browser's access cookie
  give 401 at once (cache time 0 in the API tests); the cache is unit-tested with a fake clock (reuse within the
  duration, no reuse across users, bound, failure propagation).

## Residual risks

- **Access tokens after logout (audit MEDIUM-2, closed before T16).** A copied access cookie stops working within the
  live-session cache time (default 5 s) after logout, logout-all, revoking the session, a password change or reset, or
  deactivation, on every authenticated endpoint (see "Live-session check"). The remaining window is that cache time.
  Resource APIs that validate the JWT themselves (T21) still see a stateless token valid up to 15 minutes; list this in
  the threat model (T27).
- **Login timing (audit LOW-3).** See "Residual timing difference" above. In addition, an empty password or one over
  the raw 1024 / 128 code-point caps is refused before any Verify for every account alike (it reveals nothing), but it
  still counts as a failure toward the lockout of the named account.
- **Audit volume.** `LoginFailed` rows are written for unauthenticated requests (bounded by the login rate limits) and
  their reason names the real cause: they are high-volume (short retention) and audit reads are restricted (see
  audit-and-retention.md).

## Signing keys in one process

`TokenService` builds its IdentityModel keys with signature-provider caching **off**. The default factory caches
providers process-wide by key id, so a provider could keep using a key object that `SigningKeyProvider` had already
disposed (a second host in the same process, or a reload), and signing failed with ObjectDisposedException. Found by
the T13 API tests, which start a fresh host per test. Every validation now builds a fresh signature provider: correct,
slightly more CPU per request; re-measure under load in T22 (performance) and consider caching providers in
`SigningKeyProvider` with the key objects' lifetime instead.

## Not done (optional item)

Audit saves are not wrapped: a database error while writing an audit row still fails the request (500, generic). Since
that happens on every path alike, it reveals nothing; making audit best-effort needs a logger in Auth.Services and is
left for the audit/observability task.
