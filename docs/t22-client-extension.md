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

### Options (`CentralAuthOptions`)

| Option | Default | Rule |
|---|---|---|
| `Issuer` | required | must equal the token's `iss` (central auth `Auth:Issuer`); absolute URI |
| `Audience` | required | must equal the token's `aud`: the client application's audience, or central auth's default audience in cookie mode |
| `ClientId` | null | set: the token's `client_id` must be present and equal (ordinal). null: the token must carry **no** `client_id` (a browser-session token, like the server's own cookie handler) |
| `JwksUri` | `Issuer` + `/.well-known/jwks.json` | absolute; https unless `RequireHttpsMetadata` is false |
| `RequireHttpsMetadata` | true | set false only for local development |
| `AcceptBearer` | true | `Authorization: Bearer <jwt>` |
| `AcceptCookie` | false | the access cookie (shared-domain mode only, see section 6) |
| `CookieName` | `AuthCookieNames.AccessWithDomain` | cookie mode only |
| `ClockSkew` | 30 s | 0 to 5 minutes |
| `JwksRefreshInterval` | 5 min | a cached JWKS older than this is refreshed (the server sends `max-age=300`) |
| `JwksMinRefreshInterval` | 30 s | at most one fetch per interval caused by an unknown `kid` |
| `JwksMaxStaleness` | 1 h | if refreshes keep failing, the last good JWKS is used at most this long, then the API fails closed |
| `JwksFetchTimeout` | 10 s | per fetch |

## 4. Validation (same rules as the server)

1. **Token source:**
   - The Bearer header wins. When it is present, the cookie is never consulted, and a bad Bearer token is a failure,
     not a fallback.
   - The token must be at most 8 KB.
   - No token: `NoResult`, so anonymous endpoints work.
2. **Header first, without trust:** the JWT is parsed only to read `kid` and `alg`. Malformed input is a failure.
3. **Keys** come from the JWKS cache (section 5). A `kid` the cache does not know triggers a rate-limited refresh.
4. **`JsonWebTokenHandler`** (`MapInboundClaims = false`) checks:
   - the signature, with `RequireSignedTokens`;
   - the algorithm: ES256 or RS256 only, and it must equal the matched key's own `alg` (`TryAllIssuerSigningKeys =
     false`, key resolved by `kid` **and** `alg`). This blocks `alg: none`, HS256 signed with the public key, and an
     RS256 token presented under an ES256 kid;
   - `typ` = `at+jwt` (RFC 9068), so ID tokens and other JWTs are refused;
   - `iss`, `aud`, `exp` (required) and `nbf`, with the skew. Lifetime is checked against the injected `TimeProvider`
     through a `LifetimeValidator`, so tests and the cache share one clock.
5. **`client_id` rule** (section 3), then `sub` must be a GUID.
6. **Optional session hook** (section 7).
7. **The principal:**
   - name claim `name`, role claim `role` (`[Authorize(Roles = "app:orders:editor")]` works);
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
  - uses the named `HttpClient` `CentralAuth.Jwks` (`IHttpClientFactory`), so a host can set a proxy or a handler;
  - response limit 64 KB, at most 20 keys;
  - only keys with `use` = `sig` (or no `use`) and either `kty` EC, `crv` P-256, `alg` ES256, or `kty` RSA (at least
    2048 bits), `alg` RS256 are kept. Others are ignored;
  - a JWKS with no usable key counts as a failed fetch.
- **First use, central auth unreachable:** no keys at all, so **fail closed**. The request gets 401 (never a 500, never
  an unsigned pass), an error is logged, and the next request tries again (still rate limited by
  `JwksMinRefreshInterval`).
- **Stale cache** (older than `JwksRefreshInterval`): the next request refreshes it.
  - If that fetch fails, the last good set keeps working, with a warning, until `JwksMaxStaleness`. After that, fail
    closed.
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
- **CSRF:** a cookie-authenticated request with an unsafe method (anything but GET, HEAD, OPTIONS, TRACE) must carry
  the `X-XSRF-TOKEN` header equal to the `XSRF-TOKEN` cookie (fixed-time compare). Central auth sets that cookie with
  the shared Domain (T20). This is double submit only; the API should still use SameSite and CORS. Bearer requests are
  not affected.

## 7. Live-session check: optional hook

The server checks `sid` against its refresh families on every cookie request (T16). A resource server cannot do that
from the JWKS alone.

- **Default: no check.** A token stays valid until it expires (15 minutes) after logout or revocation. This is the
  documented trade-off of self-contained tokens; keep the access-token lifetime short.
- **Hook:** if the host registers `ICentralAuthSessionValidator` (`Task<bool> IsLiveAsync(Guid userId, Guid? sessionId,
  ClaimsPrincipal principal, CancellationToken)`), it is called after validation. False, or an exception, means 401
  (fail closed).
- Central auth has no introspection endpoint today; the hook is the seam for one (or for a back-channel logout
  listener) later. The sample shows a trivial in-memory implementation in a test only.

## 8. Sample API (`samples/Auth.SampleApi`)

| Endpoint | Access |
|---|---|
| `GET /health` | anonymous |
| `GET /api/me` | any valid token; returns `sub`, `name`, roles, permissions |
| `GET /api/reports` | policy: role `app:{ClientId}:reader` (an application role) |
| `POST /api/notes` | any valid token (**Built:** an unsafe method, to show the cookie-mode XSRF rule) |

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

- **Options are read once per scheme.** The JWKS cache of a scheme is created with that scheme's options at first use;
  a configuration reload does not change a running cache (restart the API).
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
