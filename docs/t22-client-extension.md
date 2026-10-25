# AddCentralAuth() client extension and sample API (T22)

Status: **implemented.** What changed or was settled during the build is marked **Built:**.

Implementation map:

| Part | Where |
|---|---|
| Registration | `CentralAuthServiceCollectionExtensions.AddCentralAuth` (Auth.Client) |
| Options and startup checks | `CentralAuthOptions`, `CentralAuthPostConfigure`, `CentralAuthOptionsValidator` |
| Handler | `CentralAuthHandler` (internal); hook `ICentralAuthSessionValidator` |
| JWKS cache | `JwksCache` and `JwksCacheRegistry` (internal) |
| Sample | `samples/Auth.SampleApi/SampleApiProgram.cs` |

Tests:

- integration: `Client/CentralAuthClientTests`;
- unit: `Client/JwksCacheTests`;
- architecture: `ProjectReferenceTests` and `LayerDependencyTests`.

Scope: no schema change, no new package: the client uses `Microsoft.IdentityModel.JsonWebTokens`
8.23.0 (already approved, same family as the server) and the ASP.NET Core shared framework.

## 1. Goal

Another API (a "resource server") must be able to accept central-auth access tokens **using only the published JWKS**:

- no shared secret, no database, no call to central auth per request;
- the same rules as the server's own validation (T07, T18, T19);
- it keeps working across signing-key rotation.

## 2. Projects

| Project | Kind | References |
|---|---|---|
| `src/Auth.Client` | class library | `Auth.Contracts` (claim names, cookie names, OAuth error codes); package `Microsoft.IdentityModel.JsonWebTokens`; `FrameworkReference Microsoft.AspNetCore.App` |
| `samples/Auth.SampleApi` | web API (sample resource server) | `Auth.Client` only |

- The server projects (Api, Services, DAL, Entities, Contracts) never reference `Auth.Client`. `Auth.Client` never
  references the server projects other than Contracts, nor EF Core.
- **Library rules, `Auth.Client` only:**
  - every `await` uses `ConfigureAwait(false)`;
  - CA2007 is raised to an error for that folder (`.editorconfig` section);
  - the server projects keep their current style.
- The sample has an explicit `Main` in a namespaced class (`Auth.SampleApi.SampleApiProgram`), so tests can host it next
  to `Auth.Api`'s global `Program`.

## 3. Public API

```csharp
builder.Services.AddCentralAuth(builder.Configuration.GetSection("CentralAuth"));
// or
builder.Services.AddCentralAuth(o => { o.Issuer = "https://auth.example.com"; o.Audience = "api://orders"; o.ClientId = "orders"; });
```

- It registers the authentication scheme `CentralAuth` (`CentralAuthDefaults.AuthenticationScheme`) as the default
  scheme and returns the `AuthenticationBuilder`.
- The options are validated at startup (`ValidateOnStart`): a misconfigured API does not start.
- **Fix (L7, MINOR 3): restart required.** Each scheme takes one options snapshot at first use, and both the JWKS cache
  and the handler use only that snapshot, so a configuration reload can never mix settings.

### Options (`CentralAuthOptions`)

| Option | Default | Rule |
|---|---|---|
| `Issuer` | required | must equal the token's `iss` (central auth `Auth:Issuer`); absolute URI |
| `Audience` | required | must equal the token's `aud`: the client application's audience, or central auth's default audience in cookie mode |
| `ClientId` | null | set: the token's `client_id` must be present and equal (ordinal). null: the token must carry **no** `client_id` (a browser-session token, like the server's own cookie handler) |
| `JwksUri` | `Issuer` + `/.well-known/jwks.json` | absolute; https (http only when `RequireHttpsMetadata` is false); no user information; **on the issuer's host** unless `AllowForeignJwksHost` (Fix M1) |
| `AllowForeignJwksHost` | false | allow a JWKS on another host (for example a CDN) |
| `RequireHttpsMetadata` | true | set false only for local development |
| `AcceptBearer` | true | `Authorization: Bearer <jwt>` |
| `AcceptCookie` | false | the access cookie (shared-domain mode only, see section 6) |
| `CookieName` | `AuthCookieNames.AccessWithDomain` | cookie mode only; must start with `__Secure-` or `__Host-` (Fix L10) |
| `AllowedOrigins` | empty | cookie mode: required, plain origins (`https://app.example.com`) whose pages may send unsafe requests (Fix M2) |
| `ClockSkew` | 30 s | 0 to 5 minutes |
| `JwksRefreshInterval` | 5 min | a cached JWKS older than this is refreshed in the background (the server sends `max-age=300`); at most 24 h |
| `JwksMinRefreshInterval` | 30 s | at most one fetch per interval caused by an unknown `kid` |
| `JwksMaxStaleness` | 1 h | if refreshes keep failing, the last good JWKS is used at most this long, then the API fails closed; between `JwksRefreshInterval` and 24 h (Fix M3) |
| `JwksFetchTimeout` | 10 s | per fetch |

## 4. Validation (same rules as the server)

1. **Token source:**
   - The Bearer header wins. When it is present, the cookie is never consulted, and a bad Bearer token is a failure,
     not a fallback.
   - The token must be at most 8 KB.
   - No token: `NoResult`, so anonymous endpoints work.
2. **Header first, without trust:** the JWT is parsed only to read `kid` and `alg`. Malformed input, an encrypted
   token, or any `crit` header (no extension is understood, RFC 7515 4.1.11) is a failure.
3. **Keys** come from the JWKS cache (section 5). A `kid` the cache does not know triggers a rate-limited refresh.
4. **`JsonWebTokenHandler`** (`MapInboundClaims = false`) checks:
   - the signature, with `RequireSignedTokens`;
   - the algorithm: ES256 or RS256 only, and it must equal the matched key's own `alg` (`TryAllIssuerSigningKeys =
     false`, key resolved by `kid` **and** `alg`). This blocks `alg: none`, HS256 signed with the public key, and an
     RS256 token presented under an ES256 kid;
   - **why RS256 stays (L6):** central auth signs with ES256 by default, but its key store accepts RS256 keys
     (`SigningKeyAlgorithm.RS256`, CHECK `CK_SigningKey_Algorithm`). An operator may therefore publish one, and the client
     must follow. Nothing else is accepted;
   - `typ` = `AuthTokenTypes.AccessToken` (`at+jwt`, RFC 9068), so ID tokens and other JWTs are refused. **Fix (MAJOR
     1):** the constant lives in Contracts and is used by both the server's `TokenService` and the client, and a test
     checks that a server-minted token's `typ` equals it;
   - `iss`, `aud`, `exp` (required) and `nbf`, with the skew. Lifetime is checked against the injected `TimeProvider`
     through a `LifetimeValidator`, so tests and the cache share one clock.
5. **`client_id` rule** (section 3); more than one `client_id` value is refused. Then `sub` must be a GUID.
6. **Optional session hook** (section 7).
7. **The principal:**
   - name claim `name`, role claim `role` (`[Authorize(Roles = "app:orders:editor")]` works). Application roles are
     built with `AuthRoles.ApplicationRole(clientId, name)` from Contracts, the same helper the server uses (**Fix,
     MINOR 1**);
   - permissions stay as `perm` claims;
   - claim names come from `Auth.Contracts.AuthClaimTypes`.

**Failures:**

- every failure answers **401** with `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750), and no reason in the
  body;
- the shared code `OAuthErrorCodes.InvalidToken` is added to Contracts;
- the reason category is logged at Debug, never the token.

## 5. JWKS cache (rotation without per-request fetches)

- **One cache per scheme** (singleton), filled on first use. Concurrent misses share one fetch (single flight).
- **Fetch:**
  - uses the named `HttpClient` `CentralAuth.Jwks` (`IHttpClientFactory`), so a host can add a proxy or a handler;
  - **Fix (M1): redirects are never followed.** The primary handler is a `SocketsHttpHandler` with
    `AllowAutoRedirect = false`, so any 3xx is a failed fetch. An open redirect on the issuer host therefore cannot
    hand the client an attacker's JWKS. Together with the same-host rule on `JwksUri`, the keys come from the issuer's
    host only;
  - **Fix (L4):** any exception during a fetch (network, timeout, redirect, a bad document, an odd URI) is a failed
    fetch: the request gets 401, never a 500;
  - response limit 64 KB, at most 20 keys;
  - only keys with `use` = `sig` (or no `use`) and either `kty` EC, `crv` P-256, `alg` ES256, or `kty` RSA (at least
    2048 bits), `alg` RS256 are kept. Others are ignored;
  - a JWKS with no usable key counts as a failed fetch.
- **First use, central auth unreachable:** no keys at all, so **fail closed**. The request gets 401 (never a 500, never
  an unsigned pass), an error is logged, and the next request tries again (still rate limited by
  `JwksMinRefreshInterval`).
- **Stale cache** (older than `JwksRefreshInterval`). **Fix (M3): stale-while-revalidate.**
  - Requests keep getting the cached keys at once, while ONE background refresh runs (rate limited like any other
    fetch). Callers never queue behind a slow or hanging fetch.
  - If the refresh fails, the last good set keeps working until `JwksMaxStaleness` (capped at 24 h, default 1 h).
    While it does, a Warning says stale keys are being served, at most once per `JwksMinRefreshInterval`. After that,
    fail closed.
  - A key removed from the JWKS (for example after a compromise) therefore stays trusted at most
    `JwksRefreshInterval` while the JWKS is reachable, and at most `JwksMaxStaleness` while it is not.
- **Unknown `kid`** (a new key after rotation, or a forged token): one refresh, at most once per
  `JwksMinRefreshInterval` for the whole cache. A flood of random kids therefore causes at most one fetch per
  interval, never a fetch per request.
- **Rotation works without any action:**
  - central auth publishes a new key at least token lifetime plus skew before it signs (T20), so a normal stale refresh
    already has it;
  - the unknown-kid refresh covers a cache that is older than that;
  - retired keys drop out at the next refresh.

## 6. Cookie mode

- `__Host-access` is host-only: another host never receives it. A sibling API can only read the access cookie in
  shared-domain mode (`AuthCookies:Domain`, cookie `__Secure-access`, T20).
- That token has central auth's **default audience** and no `client_id`. So cookie mode means `Audience` = central
  auth's default audience and `ClientId` = null. Startup refuses `AcceptCookie` with a `ClientId`.
- **CSRF (Fix M2, MINOR 2):** a cookie-authenticated request with an unsafe method (anything but GET, HEAD, OPTIONS,
  TRACE) is refused unless:
  1. `Sec-Fetch-Site` is not `cross-site`;
  2. `Origin` is present and is one of `AllowedOrigins` (compared as lower-case scheme, host and port);
  3. the `X-XSRF-TOKEN` header equals the `XSRF-TOKEN` cookie (fixed-time compare; central auth sets that cookie with
     the shared Domain, T20).

  Bearer requests are not affected.
- **Trust boundary:** in cookie mode, **every sibling subdomain is inside the trust boundary.** A sibling can set
  cookies for the shared Domain, so it can toss its own `XSRF-TOKEN`; the double submit alone therefore proves
  nothing against a hostile sibling. The Origin allow-list is what stops other sites; binding the XSRF value to the
  session would need a change on central auth and is not built. Host only trusted applications under the shared
  Domain.
- **Confused deputy (L8):** every cookie-mode API under the shared Domain accepts the same token (central auth's
  default audience). A cookie token sent to one cookie-mode API is accepted by all the others, so they must trust each
  other. **For Bearer use, give each API its own audience** (one client application each), so a token for one API is
  refused by every other.

## 7. Live-session check: optional hook

The server checks `sid` against its refresh families on every cookie request (T16). A resource server cannot do that
from the JWKS alone.

- **Default: no check. Warning:** without a validator, logout, session revocation, a password change and account
  deactivation do **not** reach this API. A token stays valid until it expires (15 minutes). This is the trade-off of
  self-contained tokens: keep the access-token lifetime short, and register a validator if an API cannot accept it.
  The sample does not register one (it has nothing to check against); the integration tests use one.
- **Hook:** if the host registers `ICentralAuthSessionValidator` (`Task<bool> IsLiveAsync(Guid userId, Guid? sessionId,
  ClaimsPrincipal principal, CancellationToken)`), it is called after validation. False, or an exception, means 401
  (fail closed).
- **Fix (L10):** a hook that times out (`OperationCanceledException` while the request is still alive) also gives 401.
- Central auth has no introspection endpoint today; the hook is the seam for one (or for a back-channel logout
  listener) later.

### Key revocation runbook (L9)

When a signing key may be compromised (central auth side first, then what resource servers do):

1. **Put the replacement private key** in the secret store.
2. **Stop trusting the old key on central auth:** set its row to `Retired`, together with any other published key
   (`UPDATE [auth].[SigningKey] SET [Status] = N'Retired' WHERE [Kid] = @OldKid`).
   - Nothing is published now. Sign-in and refresh fail until step 3; central auth's key cache (`KeyCacheDuration`,
     1 minute) may serve the old set for up to a minute.
3. **Add the replacement with immediate activation** (`ISigningKeyRotation.AddKeyAsync(newKid, ..., activateAtUtc: now)`).
   Because nothing is published, this is the bootstrap case, and the key signs at once.
4. **Resource servers** meet the new kid and refresh at once: rate limited to one fetch per `JwksMinRefreshInterval`,
   or within `JwksRefreshInterval` in the background. The old key is gone from the JWKS, but:
   - a resource server keeps trusting it until its cached JWKS is replaced: at most `JwksRefreshInterval` (default
     5 minutes) while the JWKS is reachable, up to `JwksMaxStaleness` (default 1 hour) while it is not;
   - **restart resource servers** to drop it at once.
   - A JWKS with no usable key counts as a failed fetch (the old set is kept), which is why step 3 must follow step 2
     immediately.
5. **Revoke sessions** (logout-all for affected users, or every refresh family). Access tokens signed with the old key
   die at their expiry.

For a planned (non-emergency) rotation, use the normal overlap instead: add the new key at least token lifetime plus
skew ahead and let `RetireSupersededAsync` retire the old one. No resource server notices.

## 8. Sample API (`samples/Auth.SampleApi`)

| Endpoint | Access |
|---|---|
| `GET /health` | anonymous |
| `GET /api/me` | any valid token; returns `sub`, `name`, roles, permissions |
| `GET /api/reports` | policy: role `app:{ClientId}:reader` (an application role) |
| `POST /api/notes` | no rule of its own: the fallback policy (**Built:** an unsafe method, to show the cookie-mode CSRF rules) |

- **Fix (L5):**
  - **Default deny:** a fallback policy requires an authenticated user for every endpoint without its own rule (only
    `/health` opts out), and the Reader policy requires an authenticated user too;
  - HSTS and HTTPS redirection outside Development;
  - **no CORS on purpose:** the sample is called server to server or from its own origin. Add a CORS policy listing
    exact origins if a browser app on another origin must call it.
- Configuration: section `CentralAuth` (`Issuer`, `Audience`, `ClientId`, optional `JwksUri`).
- `appsettings.json` is not copied to the output of projects that reference the sample (tests), so it never overwrites
  `Auth.Api`'s.

## 9. Tests

**Integration** (`Auth.IntegrationTests`, the real central auth `ApiFixture` serving the JWKS to the sample host through
its TestServer handler):

- a valid app token is accepted via JWKS only (the sample has no secret and no database);
- refused, each answering 401 `invalid_token`:
  - forged (another key under the real kid), expired, wrong audience, wrong `client_id`, missing `client_id`;
  - a browser token (no `client_id`) at an app API;
  - `alg: none`, HS256 signed with the public key, wrong `typ`, a garbage token;
- **rotation:** a new key is added and becomes active (shifted clock); a token signed with it is accepted after one
  unknown-kid refresh. Retired keys are rejected after the next refresh;
- **JWKS unreachable at first use:** 401 and no crash. Once it is reachable again, it works;
- cookie mode with the XSRF double submit; Bearer wins over the cookie;
- the session hook: returning false gives 401.

**Unit** (`Auth.UnitTests`, fake handler and fake `TimeProvider`):

- single-flight first fetch;
- unknown-kid refresh at most once per interval;
- stale refresh failure keeps the last good set until `JwksMaxStaleness`;
- size and key filters;
- options validation.

**Architecture:**

- project references: `Auth.Client` references only Contracts, the sample only `Auth.Client`;
- no server project references `Auth.Client`;
- IL: `Auth.Client` has no dependency on Services, DAL, Entities, Api or EF Core;
- every `await` in `Auth.Client` uses `ConfigureAwait(false)` (CA2007 enforced by the build).

## 10. Built notes

- **Options are read once per scheme.** The JWKS cache of a scheme is created with that scheme's options at first use,
  and the handler reads every setting from that same snapshot. A configuration reload changes nothing: restart the
  API.
- **`AssemblyMarker`** (Fix MINOR 4): the architecture tests anchor on `Auth.Client.AssemblyMarker`.
- **Lifetime against the injected `TimeProvider`.** It goes through `LifetimeValidator`, which also requires `exp`.
- **The cache's rate limit covers every unplanned fetch.** That includes retries after a failed first fetch, so an API
  whose central auth is down makes at most one JWKS request per `JwksMinRefreshInterval`, not one per request.
- **A fetch has its own timeout,** never the request's cancellation, so one aborted request does not cancel the shared
  fetch for the others.
- **CA2007 is enforced for the `backend/src/Auth.Client` folder only.** An architecture test checks that the
  `.editorconfig` rule exists only there; a mutation without `ConfigureAwait(false)` fails the build.
- **Rotation test:** a shifted-clock central auth adds a key, then signs with it. With a 1-hour refresh interval, the
  sample accepts the new token only through the unknown-kid refresh (exactly one extra fetch). Five tokens with unknown
  kids right after cause no further fetch.

## 11. Out of scope

- An introspection or back-channel logout endpoint on central auth (the hook is ready for it).
- A NuGet package (`IsPackable` stays false; the project is referenced).
- Discovery (`/.well-known/openid-configuration`): the issuer and the JWKS URI are configured.
