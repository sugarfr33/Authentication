# Single logout and shared-domain cookie mode (T20)

Status: **implemented.** No schema change. Tests: `SingleLogoutApiTests` (integration), `CookieDomainRulesTests`
and `SigningKeyRotationTests` (unit).

## 1. Single logout

### The hook: `ISessionEndedPublisher`

Every path that ends sessions on the user's behalf publishes one `SessionEnded(UserId, FamilyId?, ClientApplicationId?,
Cause)` **after** its revocation. Each `ISessionEndedListener` reacts, in registration order. Adding a reaction, such
as back-channel notification later, means adding a listener, not editing the logout paths.

| Path | Cause | What the path itself revokes |
|---|---|---|
| `POST /auth/logout` | `Logout` | the browser family (from either cookie) |
| `POST /auth/logout-all` | `LogoutAll` | every family of the user |
| `DELETE /auth/sessions/{id}` | `SessionRevoked` | that family (browser or application) |
| refresh-token replay (cookie or app grant) | `TokenReuse` | the replayed family |
| password change or reset | `PasswordChange` | every family of the user |
| `POST /oauth/logout` (RP-initiated) | `ApplicationLogout` | the user's families at that application |

A listener failure propagates. The logout endpoints then clear the cookies anyway and answer 500 ("signed out in this
browser, but the session could not be ended on the server"), as before T20.

### The single-logout listener

`SingleLogoutListener` applies the rule: **when a browser session ends, every application session of that user ends
too.**

- **Why all of them:** application families are started from a browser session (the `/authorize` cookie), but nothing
  records which browser session started which application family. Recording that would add a column to
  `AuthorizationCode` or `RefreshToken`, a schema change. So ending one browser session ends all of the user's
  application sessions.
  - The trade-off: logging out on one device also signs the user out of the applications on their other devices.
    Their browser sessions on those devices stay.
- **Which causes:** `Logout`, `LogoutAll`, `SessionRevoked` of a browser family, `TokenReuse` of a browser family (a
  stolen browser session may have been used to start application sessions), and `PasswordChange`.
  - Revoking an **application** session, or an application's own logout, ends only that application's sessions: the
    browser session and the other applications stay (tested).
  - Deactivating an application ends only that application's sessions (T18; tested here too).
- **What it does:**
  - one set-based UPDATE revokes every live token of the user's application families
    (`RevokeApplicationFamiliesForUserAsync`, reason `Logout`, `LogoutAll`, `Reuse` or `PasswordChange`);
  - it drops the user's live-session cache entries on this instance;
  - it writes a `SingleLogout` audit row (cause and count; only when something was revoked).
- **Already covered before T20:** logout-all and a password change already revoked every family, applications
  included. The listener finds nothing more there, but the event still reaches every listener.
- **Not covered:** the session cap and a re-login that replaces the browser's previous session are not logouts and do
  not cascade.

### What single logout cannot stop: issued access tokens

An application access token is a bearer JWT checked by the application's resource servers against the JWKS. Revoking
its family stops the **refresh**: the next `grant_type=refresh_token` gets `invalid_grant` (tested for two
applications at once). The access token itself stays valid **until it expires**: at most
`Auth:AccessTokenLifetime`, 15 minutes by default. Shorten that lifetime for applications where this window matters.

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
- **Rate limit:** kind `OAuthLogout`, 30 per minute per IP.

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

- **Logout** expires the cookies with the same name, Domain and Path they were set with. In shared-domain mode it
  **also** expires the host-only variants (`__Host-access`, and `__Secure-refresh` without Domain), so a browser that
  still holds cookies from before a mode switch is fully signed out (tested).
- Refresh, CSRF and the live-session check work the same in both modes (tested: login, refresh, `/me`, logout, and an
  old access cookie replayed after logout is refused).

### Startup validation of the Domain (`CookieDomainRules`)

There is no public-suffix library (no new packages), so the rules are conservative. The app refuses to start unless:

- the Domain is a bare lower-case DNS name: no scheme, port, path, leading or trailing dot, and not an IP address;
- it has at least two labels of `a-z 0-9 -` (no hyphen at either end), at most 253 characters, and a non-numeric
  top-level label;
- it is not a two-label public-suffix shape: a common second-level label (`co`, `com`, `net`, `org`, `gov`, `ac`,
  ...) under a two-letter country code, so `co.uk` and `com.au` are refused;
- `Auth:Issuer` is https and its host **is** the Domain or a subdomain of it, so `example.test` is valid for
  `https://auth.example.test`, and `other.test` is not.

A Domain that passes can still be a suffix this list does not know, such as a hosting provider's shared domain. Only
use a domain you own.

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
- **Shared-domain mode loses the host-only protection of `__Host-`.**
  - Any host under the parent domain receives the access cookie (Path `/`), and the refresh cookie on its
    `/api/v1/auth` path.
  - Any host under the parent can **set or shadow** cookies for the parent domain (cookie tossing). For example, a
    compromised `blog.example.com` could plant its own `XSRF-TOKEN` or a forged `__Secure-refresh` for the parent.
    Antiforgery still holds, because the HttpOnly `__Host-antiforgery` stays host-only on the API and a planted token
    does not match it. A tossed refresh or access cookie is still only a token the server must have issued.
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
