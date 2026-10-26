# Connect a new project

There are two ways for an application to use Central Auth. Pick by **where the app lives** and **how far you trust
it**.

| | Mode A: shared-domain cookies | Mode B: OAuth Code + PKCE with JWKS |
|---|---|---|
| App location | a subdomain of the auth host's parent domain (`app.example.com` next to `auth.example.com`) | anywhere (`app.other.org`) |
| Trust | **every host under the parent domain is fully trusted** | the app is a separate party |
| SPA holds | nothing: HttpOnly cookies set by Central Auth | access and refresh tokens **in memory** |
| Its API validates | the `__Secure-access` cookie, through JWKS | `Authorization: Bearer`, through JWKS |
| Token audience | Central Auth's default audience, no `client_id` | the app's own audience and `client_id` |
| Roles in the token | global roles only | global roles plus the app's roles, as `app:{clientId}:{role}` |
| Choose when | the app is first-party and the domain hosts nothing else | everything else, and any API that should accept only its own tokens |

If in doubt, use **Mode B**. It keeps each app's tokens away from every other app.

Both modes need:

- the app's origin registered as an active **client application**, which is the CORS allow-list;
- a Central Auth issuer reachable over https.

The resource API side uses `AddCentralAuth()` from `backend/src/Auth.Client`. That API needs no database and no secret.

## Step 1 (both modes): register the application

An administrator with `apps.manage` calls the admin API from a signed-in browser session. The call needs the Origin
and `X-XSRF-TOKEN` headers, like every unsafe request.

```http
POST /api/v1/admin/apps
Content-Type: application/json

{
  "clientId": "my-app",
  "name": "My App",
  "audience": "api://my-app",
  "allowedOrigins": ["https://app.example.org"],
  "redirectUris": ["https://app.example.org/callback"],
  "postLogoutRedirectUris": ["https://app.example.org/"]
}
```

- `201` with `Location`. Rules for each field: [client-applications.md](client-applications.md), "Validation".
- Origins and redirect URIs are compared **exactly** (ordinal, character for character), and must be https outside
  Development.
- `allowedOrigins` feeds CORS and the API's Origin check. Changes reach every instance within about 30 s (cache).
- Deactivate with `POST /api/v1/admin/apps/{id}/deactivate`. Its origins, codes and refresh families stop working
  ([client-applications.md](client-applications.md), "Deactivation").
- **Mode A** uses only `allowedOrigins`; leave `redirectUris` empty.

## Mode A: shared-domain cookie mode

### A1. Central Auth settings

```text
AuthCookies:Domain = example.com            # the parent domain you own
Auth:Issuer        = https://auth.example.com   # must be https, at or under that Domain
```

- At startup the app refuses a Domain that is not a plain DNS name, is a public suffix, or is a known shared-hosting
  suffix, and it refuses an issuer outside the Domain
  ([single-logout-and-shared-domain.md](single-logout-and-shared-domain.md), "Startup validation of the Domain").
- With the Domain set:
  - the access cookie becomes `__Secure-access` with `Domain=example.com`;
  - `XSRF-TOKEN` is readable by every `*.example.com` page;
  - the refresh cookie keeps path `/api/v1/auth`.

### A2. The SPA on the sibling subdomain

Call the auth API with credentials and the double-submit header. This is the same contract as the Auth SPA's
`frontend/src/api/http.ts`, which you can copy:

```ts
const AUTH = 'https://auth.example.com/api/v1/auth';

function xsrf(): string {
  return document.cookie.split('; ').find(c => c.startsWith('XSRF-TOKEN='))?.slice('XSRF-TOKEN='.length) ?? '';
}

async function post(path: string, body?: unknown): Promise<Response> {
  return fetch(AUTH + path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-XSRF-TOKEN': decodeURIComponent(xsrf()) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// Session check: GET /me first (it also issues a fresh XSRF pair); on 401 try POST /refresh once, then GET /me again.
export const me = () => fetch(AUTH + '/me', { credentials: 'include' });
export const refresh = () => post('/refresh');
export const logout = () => post('/logout');
```

- Sign-in itself happens on the Auth SPA (`https://auth.example.com/login?returnTo=...`), or by posting
  `/auth/login` from your page.
- Always **GET before the first POST** after the session changes. The antiforgery token is bound to the user, so an
  old one gives 400.
- One refresh at a time. The Auth SPA serialises refresh across tabs with a Web Lock. A double submit within 10 s is
  tolerated; an old token replayed after that ends the whole session (reuse detection).

### A3. The sibling API

```csharp
// Program.cs of the sibling API (project reference to Auth.Client)
builder.Services.AddCentralAuth(builder.Configuration.GetSection("CentralAuth"));
```

```json
"CentralAuth": {
  "Issuer": "https://auth.example.com",
  "Audience": "https://auth.example.com",
  "AcceptCookie": true,
  "AcceptBearer": false,
  "AllowedOrigins": [ "https://app.example.com" ]
}
```

- `Audience` = Central Auth's default audience (`Auth:Audience`, which defaults to the issuer).
- **No `ClientId`.** Startup refuses `AcceptCookie` with a `ClientId`.
- Unsafe methods need `Sec-Fetch-Site` not cross-site, an `Origin` in `AllowedOrigins`, and `X-XSRF-TOKEN` equal to
  the `XSRF-TOKEN` cookie. Bearer requests skip this.
- Authorize with the `role` and `permission` claims (global roles only in this mode).

### A4. What you accept with Mode A

- **Any host under the Domain gets the access cookie and can set cookies for the whole Domain.** Never put user
  content, third-party services, marketing tools or tenant sites under it.
- **Confused deputy:** every cookie-mode API accepts the same token, so they must all trust each other. An API that
  must accept only its own tokens needs Mode B (its own audience).
- Logout ends the session for every sibling. An access token already issued stays valid for its remaining lifetime
  (up to 15 minutes) at APIs that skip the optional live-session check
  ([t22-client-extension.md](t22-client-extension.md), section 7).

## Mode B: separate app with OAuth Code + PKCE and a JWKS resource API

### B1. The app's SPA

Copy `frontend/examples/consuming-app/centralAuth.ts` into the app. Its README is the full guide.

```ts
export const auth = createCentralAuth({
  issuer: 'https://auth.example.com',
  clientId: 'my-app',
  redirectUri: 'https://app.example.org/callback',   // exactly as registered
  apiOrigins: ['https://api.example.org'],           // authFetch sends the token only here
});
router.beforeEach(createCentralAuthGuard(auth));
```

- **Flow:** `GET /api/v1/oauth/authorize` with S256 PKCE and `state`. The user signs in on the Auth SPA if needed
  (`OAuth:LoginUrl`). The app gets a code at its redirect URI, then exchanges it with `POST /api/v1/oauth/token`.
  Refresh uses `grant_type=refresh_token`.
- Tokens stay in memory. After a reload the guard starts `/authorize` again, which is a quick redirect while the
  Central Auth session lives.
- Sign out with `/api/v1/oauth/logout` (RP-initiated), and a registered `postLogoutRedirectUris` entry.
- **Send a CSP** from the app's host. Tokens in memory are only as safe as the page's scripts
  ([deployment.md](deployment.md), recommended CSP).

### B2. The app's resource API

```json
"CentralAuth": {
  "Issuer": "https://auth.example.com",
  "Audience": "api://my-app",
  "ClientId": "my-app"
}
```

```csharp
builder.Services.AddCentralAuth(builder.Configuration.GetSection("CentralAuth"));
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
```

- Bearer only by default. Keys come from `Issuer/.well-known/jwks.json` (same host required) and are cached: 5 min
  refresh, one fetch per 30 s for an unknown kid, last good set kept for at most 1 h if Central Auth is down, then
  fail closed.
- Rejected with 401, verified live in T26:
  - wrong `aud`, wrong `iss`, wrong or missing `client_id`;
  - expired;
  - a forged key with the same kid, `alg=none`, HS256 with the public key;
  - a tampered payload, a stripped signature.
- The app's roles arrive as `app:my-app:<role>` claims.
  - There is **no admin endpoint that creates roles yet**. An app-scoped role is a row in `auth.Role` with
    `ClientApplicationId` set, created by a database administrator.
  - Users are then given it with `POST /api/v1/admin/users/{id}/roles` ([authorization.md](authorization.md)).
- Working example: `backend/samples/Auth.SampleApi` (`/api/me`, a `Reader` policy, fallback policy for writes).
  - Run it locally against the dev API with `CentralAuth:JwksUri=http://localhost:5094/.well-known/jwks.json` and
    `CentralAuth:RequireHttpsMetadata=false`. The .NET client does not trust the dev certificate. **Local only.**

### B3. What you accept with Mode B

- The app's page holds tokens in memory: an XSS in the app can use them until they expire (15 minutes for access).
  Hence the CSP, and no third-party scripts on those pages.
- Logout or deactivation stops refresh at once. An already issued access token stays valid until it expires, unless
  the API adds the live-session hook.
- Resource APIs trust a removed key for at most `JwksRefreshInterval` (5 min) while the JWKS is reachable.

## Checklist

| | Mode A | Mode B |
|---|---|---|
| Client application registered, origin exact | yes | yes, plus redirect and post-logout URIs |
| Central Auth setting | `AuthCookies:Domain` | none |
| SPA | `credentials: 'include'`, `X-XSRF-TOKEN`, GET before POST | `centralAuth.ts`, tokens in memory, CSP |
| API options | `AcceptCookie`, default audience, no `ClientId`, `AllowedOrigins` | own `Audience` and `ClientId`, bearer |
| Read next | [single-logout-and-shared-domain.md](single-logout-and-shared-domain.md) | [authorization-code-pkce.md](authorization-code-pkce.md), [t22-client-extension.md](t22-client-extension.md) |
