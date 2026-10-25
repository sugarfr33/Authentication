# Single logout and shared-domain cookie mode (T20)

Status: **implemented** (T20 plus the review fixes). No schema change.

Tests:

- integration: `SingleLogoutApiTests`, `CookieAuthTests`;
- unit: `CookieDomainRulesTests`, `SessionEndRulesTests`, `SigningKeyRotationTests`;
- architecture: `SessionStartCallSiteTests`, whose IL scan checks that every type that revokes sessions publishes.

## 1. Single logout

### The hook: `ISessionEndedPublisher`

`SessionEnded(Scope, Cause, UserId?, FamilyId?, ClientApplicationId?, RoleId?)` says what ended. The **scope is stated
by the publisher**, never inferred by a listener:

- **`Browser`:** a browser session of the user.
- **`Application`:** sessions at one application. That is one family, the user's sessions there, or every user's
  sessions there (`UserId` null).
- **`All`:** every session of the user, or of every holder of `RoleId` (`UserId` null).

Each `ISessionEndedListener` reacts, **in DI registration order** (`SingleLogoutListener` is registered first). A
reaction added later, such as back-channel notification, is one more listener.

| Path | Scope | Cause | Published |
|---|---|---|---|
| `POST /auth/logout` | Browser | `Logout` | **before** the browser family is revoked |
| login replacing **another user's** session in the same browser | Browser | `Logout` | before |
| `DELETE /auth/sessions/{id}`, browser family | Browser | `SessionRevoked` | before |
| `DELETE /auth/sessions/{id}`, application family | Application | `SessionRevoked` | after |
| `POST /auth/logout-all` | All | `LogoutAll` | after |
| browser refresh-token replay | Browser | `TokenReuse` | after (the rotation revoked it) |
| application refresh-token replay | Application | `TokenReuse` | after |
| refresh with a disabled or unverified account | Browser or Application | `AccountDisabled` | after |
| password change or reset | All | `PasswordChange` | after |
| email verification (the pending password takes effect) | All | `EmailVerified` | after |
| role removed from a user | All (user) | `AdminRevoked` | after |
| permission removed from a role | All (`UserId` null, `RoleId`) | `AdminRevoked` | after |
| application deactivated, or its audience changed | Application (`UserId` null) | `ApplicationDeactivated` | after |
| authorization code replayed | Application | `CodeReplay` | after |
| `POST /oauth/logout` (RP-initiated) | Application | `ApplicationLogout` | the listener revokes |

**Deliberately silent** (pinned by the architecture test's exception list):

- **session-cap eviction:** a consequence of starting a new session, not an ending the user asked for;
- **the revocation primitive itself** (`RefreshTokenService`): the reuse revocation inside a rotation is published by
  the refresher;
- **a refresh that fails after rotation:** the new token was never handed out;
- **the listener's own revocations.**

The same user signing in again over their own session stays silent too: they keep their application sessions.

**Failure and retry.** A listener failure becomes `SessionEndFailedException`.

- For the Browser-scope events of logout and session revoke, publishing happens **before** the browser family is
  revoked. A failure therefore leaves the browser session as it was: the endpoint answers 500 ("nothing changed in
  this browser; retry") **without clearing the cookies**, and the user can retry (tested with a throwing listener).
- `POST /oauth/logout` answers `500 {"error":"server_error"}` and changes nothing for the browser.
- Any other failure after the browser family was revoked keeps the earlier behaviour: cookies cleared, then 500.

### The single-logout listener

`SingleLogoutListener` is the **one owner** of application-session endings caused by the user, and of the
`SingleLogout` audit.

- **Browser scope:** every application session of that user ends.
  - **Why all of them:** application families are started from a browser session (the `/authorize` cookie), but
    nothing records which browser session started which application family. Recording that would add a column, a
    schema change.
  - The trade-off: signing out on one device also signs the user out of the applications on their other devices.
    Their browser sessions there stay, so the applications silently re-authorize through `/authorize`.
- **`ApplicationLogout`:** the user's sessions at that application end. The browser and the other applications stay.
- **Anything else:** no cascade. The publisher already revoked everything in scope.
- **Reasons:** each cascading cause maps to a revocation reason (`Logout`, `Reuse` or `Admin`). An unmapped cause
  **throws**, so a new cause (for example MFA reset in T21) can never cascade silently as a logout.
- **What it does:**
  - one set-based UPDATE (`RevokeApplicationFamiliesForUserAsync`);
  - drops the user's live-session cache entries on this instance when it revoked something;
  - writes a `SingleLogout` audit row with the cause and the count. For a browser cascade the row is written only
    when something was revoked; an application logout always writes one, with the application id.
- **Live-session cache:** each path drops what **it** revokes, and the listener drops what **it** revokes.

### What single logout cannot stop: issued access tokens

An application access token is a bearer JWT checked by the application's resource servers against the JWKS. Revoking
its family stops the **refresh**: the next `grant_type=refresh_token` gets `invalid_grant` (tested for two
applications at once). The access token itself stays valid **until it expires**: at most
`TokenOptions.AccessTokenLifetime`, 15 minutes, which is set in code today; making it configurable is a noted
follow-up. Keep it short where this window matters.

Back-channel logout (telling each application's server to drop its state) is **future work**. It needs a registered
logout endpoint per application, which is a schema change.

### RP-initiated logout: `/api/v1/oauth/logout`

Parameters: `client_id`, optional `post_logout_redirect_uri`, optional `state` (the same names in the query and in the
JSON body).

- **`GET`, anonymous:** validates and describes; it **never changes state and never redirects**.
  - Answer: `200 {"client_id": "...", "redirect_to": "...or null"}`.
  - The auth UI shows a confirmation, then POSTs.
- **`POST`, JSON:**
  - needs the **browser session cookie** (`RequireAuthorization`), the Origin check and the antiforgery token, like
    every state-changing request;
  - **bound to the caller:** the request `Origin` must be one of the **named application's own** registered origins,
    or our auth UI (the API's own origin or `BrowserProtection:TrustedOrigins`). Otherwise the answer is
    `400 invalid_client` and nothing changes. A sibling application on the shared domain therefore cannot end the
    user's sessions at another application (tested);
  - a Bearer application token is not a session here: it gets 401 (tested);
  - revokes the user's families **at that application only**, publishes `ApplicationLogout` and audits `SingleLogout`
    with the application;
  - answers like GET. The browser session on the auth domain **stays**: to sign out of everything, the UI then calls
    `/auth/logout`.
- **Where to send the browser afterwards:** `redirect_to` is set **only** when `post_logout_redirect_uri` is
  character for character (ordinal) one of the application's registered post-logout URIs.
  - The URI comes from the registry, read through the cached view, so changes reach other instances within 30 s.
  - A valid `state` (1 to 512 visible ASCII characters) is appended.
  - Any other value (unregistered, prefix, extra path, case, user info, fragment, added query) gives `redirect_to: null`:
    the UI stays on our domain (tested).
  - The server never answers with a `Location`. The UI navigates to the server-built `redirect_to`, so a cross-origin
    fetch never follows a redirect.
- **Errors:**
  - unknown or inactive client: `400 {"error":"invalid_client"}`;
  - duplicate parameters or a query over 4 KB: `400 {"error":"invalid_request"}`;
  - never a redirect.
- All answers are `no-store`, `Pragma: no-cache` and `Referrer-Policy: no-referrer`.
- **Rate limit:** kind `OAuthLogout`, 30 per minute per IP, with GET and POST counted together.
  - There is no per-user limit: the POST needs a signed-in session and only ends that user's own sessions.
  - The registry refuses fragments in post-logout URIs, as it does for redirect URIs, so the `state` appended to a
    target never lands inside a fragment (validator tests).

## 2. Cookie modes

`AuthCookies:Domain` selects the mode per environment.

| | Host-only mode (Domain empty, the default) | Shared-domain mode (Domain set, e.g. `example.com`) |
|---|---|---|
| Access cookie | `__Host-access`, no Domain, Path `/` | `__Secure-access`, `Domain=example.com`, Path `/` |
| Refresh cookie | `__Secure-refresh`, no Domain, Path `/api/v1/auth` | `__Secure-refresh`, `Domain=example.com`, Path `/api/v1/auth` |
| `XSRF-TOKEN` (readable) | no Domain | `Domain=example.com`, so a SPA on a sibling subdomain can read it |
| `__Host-antiforgery` (HttpOnly) | host-only | host-only (only the API reads it) |
| Who can use the cookie session | pages on the API's own origin | SPAs on `*.example.com` (same site), with `credentials: include` |
| Other domains | OAuth Authorization Code + PKCE | OAuth Authorization Code + PKCE |

All cookies are `Secure` and `HttpOnly` (except `XSRF-TOKEN`). The access cookie is SameSite Lax by default (or
Strict); the refresh, XSRF and antiforgery cookies are SameSite Strict.

- **Logout** expires the cookies with the same name, Domain and Path they were set with.
- **Every write in shared-domain mode** (login, refresh, the XSRF token and logout) first expires the **host-only twin**
  of the same name: `__Host-access`, and `__Secure-refresh` and `XSRF-TOKEN` without Domain.
  - Without this, a browser switched from host-only to shared mode would keep the old host-only refresh cookie and send
    both. The stale one goes first, so it would be rotated or refused, and reuse detection would loop the user out
    (tested: the response carries the expired twins before the Domain cookies).
- **Switching back** from shared to host-only: the Domain cookies cannot be named any more, so users sign out once.
  Otherwise the old Domain cookies expire after at most the refresh lifetime.
- **Duplicate auth cookies are refused** in shared-domain mode (`DuplicateCookieGuardMiddleware`, before
  authentication).
  - A request carrying `__Secure-access`, `__Secure-refresh` or `XSRF-TOKEN` more than once gets 400, and the answer
    expires the host-only twins, so a legitimate browser recovers on its next request.
  - Each rejection is counted in the `auth.cookies.duplicate_rejected` metric and logged without values (tested).
  - The usual cause is a leftover twin; the dangerous one is cookie tossing (below).
- Refresh, CSRF and the live-session check work the same in both modes (tested: login, refresh, `/me`, logout, and an
  old access cookie replayed after logout is refused).

### Startup validation of the Domain (`CookieDomainRules`)

There is no public-suffix library (no new packages), so the rules are conservative and include a small built-in
deny list. The app refuses to start unless:

- the Domain is a bare lower-case DNS name: no scheme, port, path, leading or trailing dot, and not an IP address;
- it has at least two labels of `a-z 0-9 -` (no hyphen at either end), at most 253 characters, and a non-numeric
  top-level label;
- it is not a two-label public-suffix shape: a common second-level label (`co`, `com`, `net`, `org`, `gov`, `ac`,
  ...) under a two-letter country code, so `co.uk` and `com.au` are refused;
- it is not a known shared-hosting suffix, and not a name directly under one: `herokuapp.com`, `azurewebsites.net`,
  `github.io`, `vercel.app`, `netlify.app`, `pages.dev`, `appspot.com`, `blogspot.com`, `amazonaws.com`,
  `cloudfront.net`, `onrender.com` and more. More second-level labels are refused too, such as `gouv` and `asso`;
- `Auth:Issuer` is https and its host, compared in punycode form (`Uri.IdnHost`), **is** the Domain or a subdomain of
  it, so `example.test` is valid for `https://auth.example.test`, and `other.test` is not.

A Domain that passes can still be a suffix these lists do not know. Only use a domain you own.

### Per environment

| Environment | Recommended `AuthCookies:Domain` | Notes |
|---|---|---|
| Development | empty | API and SPA on `localhost` ports; same site. |
| Test / staging | empty, or the staging parent (`staging.example.com`) to rehearse shared-domain mode | Issuer must be https under it. |
| Production, SPA on a sibling subdomain | the parent (`example.com`) | Apply the trade-offs below. |
| Production, SPAs on other domains | empty | They use the OAuth flow; the cookie session stays on the API host. |

### Threat trade-offs

- **A SPA on a different registrable domain** (`app.other.com` against `auth.example.com`) can never read
  `XSRF-TOKEN`, and our cookies are third-party to it. Use the OAuth Authorization Code + PKCE flow instead
  (authorization-code-pkce.md); that is what it is for.
- **HARD REQUIREMENT for shared-domain mode: every host under the Domain is fully trusted.** Never put user content,
  third-party services, marketing tools or tenant sites under it. Any host there receives the access cookie, can read
  `XSRF-TOKEN`, and can set cookies for the whole domain. Host-only mode stays the default.
- **Shared-domain mode loses the host-only protection of `__Host-`.**
  - Any host under the parent domain receives the access cookie (Path `/`), and the refresh cookie on its
    `/api/v1/auth` path.
  - Any host under the parent can **set or shadow** cookies for the parent domain (cookie tossing). For example, a
    compromised `blog.example.com` could plant its own `XSRF-TOKEN` or a forged `__Secure-refresh` for the parent.
    Antiforgery still holds, because the HttpOnly `__Host-antiforgery` stays host-only on the API and a planted token
    does not match it. A tossed refresh or access cookie is still only a token the server must have issued.
  - A tossed cookie usually arrives **next to** ours (another Path or host-only), so the request carries the name twice
    and is refused (above). A tossed cookie that exactly **replaces** ours (same name, Domain and Path) can only sign
    the browser out or in as whatever session the attacker holds (session fixation). That is why every host under the
    Domain must be trusted.
- **Recommendations for shared-domain mode:**
  - keep untrusted or third-party content off the parent domain (use a separate registrable domain for user content,
    marketing tools and so on);
  - keep the refresh cookie on its narrow Path;
  - keep the access-token lifetime short;
  - set a strict CSP on every app under the parent;
  - prefer host-only mode whenever the SPA can be served from the API's origin or use the OAuth flow.

## 3. Signing-key overlap rule (from the T07/T09 review)

`ISigningKeyRotation.AddKeyAsync` treats a key as the bootstrap key only when **no key is published at all**.

- Whenever any key is published, even one dated in the future that does not sign yet, a new key must activate at
  least `KeyOverlap` (token lifetime plus clock skew) after now.
- The reason: resource servers may already have cached the published set, so a new key needs the same publication
  head start (tested: with only a future key published, a new key can no longer start now).
