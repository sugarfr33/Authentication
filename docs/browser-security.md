# Cookie transport, CSRF and CORS (T10)

## Tokens travel only in cookies

`ICookieWriter` (Auth.Api) is the only way tokens leave the API. Bodies, URLs and script-readable headers never carry
them; an integration test scans every response for JWTs and the token values.

| Cookie | Flags | Path | Max-Age |
|---|---|---|---|
| `__Host-access` (access JWT) | HttpOnly, Secure, SameSite=Lax (configurable Strict), no Domain | `/` | remaining token lifetime (15 min) |
| `__Secure-refresh` (opaque refresh token) | HttpOnly, Secure, SameSite=Strict | `/api/v1/auth` only (T13 fix: was `/api/v1/auth/refresh`) | remaining refresh lifetime (up to 14 days) |
| `__Host-antiforgery` (antiforgery cookie token) | HttpOnly, Secure, SameSite=Strict | `/` | session |
| `XSRF-TOKEN` (antiforgery request token) | **readable by script, by design**, Secure, SameSite=Strict | `/` | session |

- `Secure` is set in every environment, Development included: the `__Host-`/`__Secure-` prefixes require it, and
  browsers accept Secure cookies from `http://localhost`.
- `AuthCookies:Domain` (shared-domain mode, T20) adds a Domain to the cookies and renames the access cookie to
  `__Secure-access`, because `__Host-` forbids a Domain. With no Domain configured (the default) cookies are host-only.
- Logout: `ClearAuthCookies` re-sends both cookies empty, `Max-Age=0` and `Expires=1970`, with the same name, path,
  domain and flags they were set with.

## Authentication

`AccessTokenCookieHandler` reads **only** the access cookie (an `Authorization` header is ignored), validates the JWT
with `ITokenService.ValidateAsync` (parameters fetched per request from the cached key provider: issuer, audience,
lifetime, at+jwt type, pinned algorithm, kid-matched published key), and builds the principal with `name` and `role`
as the name and role claim types. Any failure gives a bare 401 ProblemDetails. Forbidden gives 403 ProblemDetails.

## CSRF: antiforgery and Origin checks

`BrowserProtectionMiddleware` runs after authentication:

1. **GET/HEAD under `/api`** issue the antiforgery pair (ASP.NET Core antiforgery, tokens signed and bound to the
   signed-in user).
2. **Every other method except OPTIONS** (POST, PUT, PATCH, DELETE, ...) must pass both checks:
   - **Origin**: the `Origin` header, or the `Referer` origin when Origin is absent, must be the API's own origin, a
     `BrowserProtection:TrustedOrigins` entry (e.g. the auth UI) or an active client application's AllowedOrigin.
     `Origin: null`, malformed values and look-alike hosts are rejected with **403** ProblemDetails.
   - **Antiforgery**: header `X-XSRF-TOKEN` must carry the `XSRF-TOKEN` cookie value. A missing or wrong token gives
     **400** ProblemDetails.
3. A request with **neither Origin nor Referer** is rejected (403) by default. **Non-browser clients:** set
   `BrowserProtection:AllowMissingOrigin=true` to let such requests skip the origin check only. They still need a
   valid antiforgery token. **This flag is refused outside Development: startup fails.**

Because antiforgery tokens are bound to the user, **the SPA must fetch a fresh `XSRF-TOKEN` (any GET under /api) after
sign-in and sign-out** before its next state-changing call. T13's login and logout responses should reissue it.

## CORS

`ClientApplicationCorsPolicyProvider` builds the policy per request:

- The allowed origins are active client applications' `AllowedOrigin` entries (from `IClientApplicationOriginProvider`,
  a singleton cache with a 30 s TTL) plus `BrowserProtection:TrustedOrigins`. Inactive applications are excluded.
- For an allowed origin, the policy lists **exactly that origin** with `Access-Control-Allow-Credentials: true`,
  methods GET/POST/PUT/PATCH/DELETE, headers `Content-Type` and `X-XSRF-TOKEN`, and preflight max-age 10 min.
- An unknown origin gets **no CORS headers**. A wildcard is impossible: entries like `*`, `https://*.x` or `null` are
  rejected when the list is read.
- The policy carries the **normalized** origin (lower case, no trailing slash), never the raw header value.
- **Outside Development every allowed origin must be https**: plain http is accepted only for loopback hosts
  (`localhost`, `127.0.0.1`, `[::1]`). Insecure client-application entries are skipped. An insecure or wildcard
  `BrowserProtection:TrustedOrigins` entry stops startup. In Development, http origins are accepted.
- Every response carries `Vary: Origin`.

Same-origin detection compares the request's scheme and host. Behind a reverse proxy, forwarded headers must be
configured (deployment task) so the API sees the public scheme and host.
