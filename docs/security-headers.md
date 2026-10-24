# Security headers and host settings (T09)

`Auth.Api` adds these headers to **every** response, error responses included (`SecurityHeadersMiddleware`):

| Header | Value | Why |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTPS only. Sent on HTTPS responses outside Development. Plain HTTP is redirected to HTTPS (`UseHttpsRedirection`, also outside Development). |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | The API returns JSON only, so nothing may load, and it may not be framed. |
| `X-Content-Type-Options` | `nosniff` | No MIME sniffing. |
| `X-Frame-Options` | `DENY` | Legacy fallback for `frame-ancestors`. |
| `Referrer-Policy` | `no-referrer` | Never leak URLs (which may carry codes) to other sites. |
| `Permissions-Policy` | every powerful feature disabled (`camera=()`, `geolocation=()`, ...) | The API needs none of them. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context. |
| `Vary` | `Origin` | CORS headers are computed per request Origin, so caches (e.g. for the public JWKS) must key on it. |
| `Cache-Control` | `no-store` (plus `Pragma: no-cache`) unless an endpoint sets its own | Auth responses must never be cached. The JWKS sets `public, max-age=300`. |

The `Server` header is removed (Kestrel `AddServerHeader = false`).

## CSP for the Vue auth UI (later tasks)

The API's CSP is deliberately `default-src 'none'`. The Vue SPA (served from its own origin, A14) needs its own policy
from whatever serves it, as a starting point:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
connect-src 'self' https://<api-host>; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
object-src 'none'; upgrade-insecure-requests
```

- No `'unsafe-inline'` or `'unsafe-eval'` (Vite production builds do not need them; dev server excluded).
- `connect-src` must list the API origin, which must also be in the API's CORS policy (T10).
- If a nonce or hash becomes necessary for inline bootstrapping, prefer `'strict-dynamic'` with a per-response nonce.

## Hosts and secrets

- `AllowedHosts` (host filtering) must list the real public host names. Outside Development the app **refuses to
  start** if it is empty or `*` (`HostingGuards`). Set it per environment, e.g. the `AllowedHosts` environment variable.
- `https_port` tells HTTPS redirection the public HTTPS port when it cannot be discovered (e.g. behind a proxy).
- Secrets (the `ConnectionStrings:CentralAuth` value, `Secrets:<name>` signing keys) come only from environment variables or
  User Secrets (Development). `appsettings.json` and `appsettings.Development.json` contain none; an architecture test
  enforces this. `appsettings.Example.json` documents the placeholders.

## Errors and logging

- Unhandled exceptions return a generic RFC 9457 ProblemDetails 500 (`title`, `status`, `traceId`). No message or stack
  trace is returned, except in the Development environment with `Errors:IncludeExceptionDetails=true` (default false).
- Serilog with `RedactionEnricher`: properties named like passwords, tokens, cookies, authorization, secrets, connection
  strings or API keys are replaced with `[REDACTED]`. All other string values are scrubbed of `Bearer ...`,
  `password=...`/`token=...`/`code=...` pairs and JWTs. Request logging records the path without the query string.
  Exceptions are logged by `GlobalExceptionHandler` as redacted text; ASP.NET Core's own unhandled-exception log is
  turned off so the raw exception is not logged twice.

## Health

- `/health`: liveness, always `200 Healthy` while the process answers.
- `/health/ready`: readiness, checks the database within 5 s. Returns `200 Healthy` or `503 Unhealthy`, with no details.
