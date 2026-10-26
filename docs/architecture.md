# Architecture

Central Auth is one ASP.NET Core (.NET 10) API on SQL Server, plus a Vue 3 SPA for sign-in and account pages. Other
applications trust it in one of two ways ([connect-a-project.md](connect-a-project.md)):

- **shared-domain cookie mode**, for trusted apps under the same parent domain;
- **OAuth Authorization Code + PKCE**, for apps anywhere else. Their APIs validate bearer tokens against JWKS.

## System context

```mermaid
flowchart LR
    user(["User's browser"])

    subgraph central["Central Auth (auth.example.com)"]
        spa["Auth SPA<br/>Vue 3: sign-in, register, MFA, account"]
        api["Auth.Api<br/>/api/v1/auth, /oauth, /admin<br/>/.well-known/jwks.json"]
        db[("SQL Server<br/>schema auth")]
        secrets[["Secret store<br/>signing PEMs, MFA keys"]]
        mail[["Email sender"]]
    end

    subgraph sibling["Same parent domain (cookie mode)"]
        sspa["Sibling SPA<br/>app.example.com"]
        sapi["Sibling API<br/>AddCentralAuth, AcceptCookie"]
    end

    subgraph other["Any other domain (OAuth + PKCE)"]
        ospa["App SPA<br/>tokens in memory"]
        oapi["Resource API<br/>AddCentralAuth, bearer"]
    end

    user --> spa
    user --> sspa
    user --> ospa
    spa -->|"cookies + X-XSRF-TOKEN"| api
    sspa -->|"shared-domain cookies"| api
    sspa -->|"__Secure-access cookie"| sapi
    ospa -->|"/oauth/authorize, /oauth/token"| api
    ospa -->|"Authorization: Bearer"| oapi
    sapi -.->|"JWKS, cached"| api
    oapi -.->|"JWKS, cached"| api
    api --> db
    api --> secrets
    api --> mail
```

## Backend layers

```mermaid
flowchart TB
    apiProj["Auth.Api<br/>endpoints, middleware, hosting"]
    services["Auth.Services<br/>sign-in, tokens, lockout, MFA, admin"]
    dal["Auth.DAL<br/>EF Core, repositories, migrations"]
    entities["Auth.Entities<br/>table classes"]
    contracts["Auth.Contracts<br/>requests, responses"]
    client["Auth.Client<br/>AddCentralAuth for other APIs"]
    sample["samples/Auth.SampleApi"]

    apiProj --> services
    apiProj --> contracts
    services --> dal
    services --> entities
    services --> contracts
    dal --> entities
    client --> contracts
    sample --> client
```

- Services never reference EF Core. The DAL keeps EF's compile assets private.
- `Auth.ArchitectureTests` enforces these arrows (NetArchTest).
- Auth.Client has no database and no secret. It needs only the issuer and its JWKS.

## Request pipeline (Auth.Api)

```mermaid
flowchart TB
    r["Request"] --> fwd["Forwarded headers<br/>only from KnownProxies"]
    fwd --> hdr["Security headers<br/>CSP none, nosniff, HSTS on https"]
    hdr --> err["Exception handler<br/>generic ProblemDetails"]
    err --> https["HTTPS redirection<br/>not in Development"]
    https --> cors["CORS<br/>registered app origins only"]
    cors --> rl["Rate limiter<br/>per IP and per account"]
    rl --> dup["Duplicate-cookie guard"]
    dup --> authn["Authentication<br/>access cookie or bearer, live-session check"]
    authn --> bp["Browser protection<br/>Origin check and antiforgery"]
    bp --> authz["Authorization<br/>default deny, permission policies"]
    authz --> ep["Endpoint"]
```

Host filtering (`AllowedHosts`) runs before all of these, on every request.

## Browser sign-in and refresh (the Auth SPA)

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (SPA)
    participant A as Auth.Api
    participant D as Database

    B->>A: GET /api/v1/auth/me
    A-->>B: 401, sets __Host-antiforgery and XSRF-TOKEN
    B->>A: POST /auth/login with Origin and X-XSRF-TOKEN
    A->>D: check lockout, verify Argon2id hash
    A->>D: new refresh family, audit
    A-->>B: 200 profile only, sets __Host-access (15 min) and __Secure-refresh (path /api/v1/auth)
    Note over B,A: later, the access cookie expires
    B->>A: GET /auth/me (401), then POST /auth/refresh
    A->>D: rotate refresh token in the same family
    A-->>B: 204, new cookies
    Note over A,D: an old refresh token replayed after the 10 s grace window revokes the whole family (TokenReuse audit)
```

No token ever appears in a response body, a URL or `localStorage`.

## OAuth Authorization Code + PKCE (apps on other domains)

```mermaid
sequenceDiagram
    autonumber
    participant S as App SPA
    participant A as Auth.Api
    participant L as Auth SPA (/login)
    participant R as App resource API

    S->>S: make code_verifier and state, challenge = S256(verifier)
    S->>A: GET /oauth/authorize?client_id, redirect_uri, code_challenge, state
    alt not signed in
        A-->>L: 302 to OAuth:LoginUrl with returnTo
        L->>A: sign in (cookie session)
        L-->>A: back to /oauth/authorize
    end
    A-->>S: 302 to the registered redirect_uri with code and state
    S->>A: POST /oauth/token (code, code_verifier, client_id, redirect_uri) with its Origin
    A-->>S: access_token (aud = the app's audience), refresh_token, Cache-Control no-store
    S->>R: Authorization: Bearer access_token
    R->>A: GET /.well-known/jwks.json (cached, refreshed on unknown kid)
    R-->>S: 200, or 401 or 403
```

- Unknown clients and unregistered redirect URIs get an error page and **never a redirect**.
- Codes are single use, live 1 minute, and are bound to the client, the exact redirect URI and the PKCE challenge.

Details: [authorization-code-pkce.md](authorization-code-pkce.md).

## Data

Thirteen tables in schema `auth`, plus `__EFMigrationsHistory` (`docs/CentralAuth.initial.sql`):

- `User`, `RefreshToken` (hashed values, rotation families), `SigningKey` (public JWKs only);
- `ClientApplication`, `AuthorizationCode`;
- `Role`, `Permission`, `RolePermission`, `UserRole`;
- `EmailVerificationToken`, `PasswordResetToken`, `MfaRecoveryCode`;
- `AuditLog`.

Retention jobs purge expired rows ([audit-and-retention.md](audit-and-retention.md)).

## Where to read more

| Topic | Document |
|---|---|
| Local setup, clean clone | [setup.md](setup.md) |
| Production settings | [deployment.md](deployment.md) |
| Connecting another app | [connect-a-project.md](connect-a-project.md) |
| Threats, controls, residual risks | [threat-model.md](threat-model.md) |
| Sessions, cookies, refresh | [sign-in-and-sessions.md](sign-in-and-sessions.md), [browser-security.md](browser-security.md) |
| Cookie modes, single logout | [single-logout-and-shared-domain.md](single-logout-and-shared-domain.md) |
| Client library | [t22-client-extension.md](t22-client-extension.md) |
| Tests per scenario | [test-matrix.md](test-matrix.md) |
| Packages | [packages.md](packages.md) |
