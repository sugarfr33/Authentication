# Deployment notes

What changes between the local setup ([setup.md](setup.md)) and a real environment. Every setting the API reads is
listed in `backend/src/Auth.Api/appsettings.Example.json`. Header and host basics are in
[security-headers.md](security-headers.md).

## Checklist

| # | Item | Setting or action |
|---|---|---|
| 1 | Environment | `ASPNETCORE_ENVIRONMENT=Production`. Development-only behaviour (plain http allowed, file email, exception details) switches off. |
| 2 | Public host names | `AllowedHosts=auth.example.com` (no `*`; startup refuses it). See "Host filtering and load-balancer probes" below. |
| 3 | Issuer and audience | `Auth:Issuer` and `Auth:Audience` = the public https URL of the API. |
| 4 | Database | `ConnectionStrings:CentralAuth` from the environment or a secret store. Apply migrations before the new version starts (the API does not migrate at startup): `dotnet ef migrations script --idempotent` or `docs/CentralAuth.initial.sql`. |
| 5 | Signing key | First key: [setup.md](setup.md) step 3 (recipe), with the PEM in the secret store (`Secrets__<kid>` or `SecretFiles__<kid>`, kid of letters, digits and underscores). Later keys: overlap rule below. |
| 6 | Reverse proxy | `ForwardedHeaders:KnownProxies`, or `ForwardedHeaders:Direct=true` when nothing sits in front. See next section. |
| 7 | SPA URLs | `AccountEmail:VerifyEmailUrl`, `AccountEmail:ResetPasswordUrl` and `OAuth:LoginUrl` (`<spa>/login`), all https. |
| 8 | SPA client app | `ClientApplications:Bootstrap` with the SPA's https origin in `AllowedOrigins`. |
| 9 | SPA headers | The host that serves the SPA must send a CSP (below), and serve `index.html` for unknown paths. |
| 10 | Email | Register a real `IEmailSender` (a code change). Outside Development the shipped sender refuses to send (`UnconfiguredEmailSender`), so registration and password reset fail until then. |
| 11 | First admin | `Authorization:BootstrapAdminEmail` once, restart, then remove it ([authorization.md](authorization.md)). |
| 12 | MFA | `Mfa:Enabled`, with the secrets `MfaEncryptionKey-<id>` and `MfaRecoveryPepper` in the secret store ([mfa-totp.md](mfa-totp.md)). The fixed names contain a hyphen; see [setup.md](setup.md), "Naming rule for secrets". |
| 13 | Cookie mode | `AuthCookies:Domain` empty (host-only), or the shared parent domain ([connect-a-project.md](connect-a-project.md)). |

## Behind a TLS-terminating proxy (from the T09 review)

The API sends HSTS and redirects http to https only when it believes the request came over HTTPS
(`Request.IsHttps`). Behind a proxy that terminates TLS, the request reaching Kestrel is plain http. So:

- **Without `ForwardedHeaders:KnownProxies`**, `X-Forwarded-Proto` is ignored and every request looks like http:
  - `UseHttpsRedirection` answers each request with a redirect to https. The browser follows it, the proxy forwards
    plain http again, and the result is a **redirect loop**.
  - **HSTS is never sent**, because the request is not "https".
  - The client IP is the proxy's, so all users share one per-IP rate-limit bucket. `ProxyMisconfigurationDetector`
    logs a warning per instance.
- **Fix:** list the proxy's address in `ForwardedHeaders:KnownProxies` (environment `ForwardedHeaders__KnownProxies__0`).
  The API then trusts `X-Forwarded-For` and `X-Forwarded-Proto` from that address only, **one hop deep**
  (`ForwardLimit = 1`).
  - Only single IP addresses are accepted, no CIDR ranges. A proxy pool with changing addresses (some container or
    PaaS ingress) needs each address listed, or a proxy that keeps a stable address.
  - Make sure the proxy **overwrites** `X-Forwarded-For` and `X-Forwarded-Proto` rather than appending to what the
    client sent.
- **Nothing in front** (Kestrel terminates TLS itself): set `ForwardedHeaders:Direct=true` to silence the detector.
- Set `https_port` when the public https port cannot be discovered (default 443 in the example settings).

## Host filtering and load-balancer probes

`AllowedHosts` is enforced on **every** request, including `/health` and `/health/ready`. A request whose `Host`
header is not listed gets **400**.

- Many load balancers probe with the instance IP or an internal name as `Host`. The probe then sees 400, marks the
  instance unhealthy, and takes it out of rotation.
- **Fix:** configure the probe to send the public host name as `Host` (most load balancers support a custom host
  header), or add the exact internal probe host name to `AllowedHosts` (`auth.example.com;auth-internal.local`).
  Never use `*`.
- Probe `/health` for liveness and `/health/ready` for readiness. Both answer just a status word.

## Signing keys after the first one

- A new key must be published (in JWKS) at least the access-token lifetime plus clock skew before it signs.
  `ISigningKeyRotation.AddKeyAsync` enforces this; it is how keys after the first should be added.
- There is no admin endpoint or CLI for key rotation yet; it runs from code (a maintenance host).
- Revocation and resource-server caches: [t22-client-extension.md](t22-client-extension.md), "Key revocation runbook".

## Recommended Content-Security-Policy for the SPA

No CSP ships with the SPA. `frontend/index.html` has no `<meta>` policy, so the server or CDN that serves the built
files must send one. The API's own responses already carry a strict `default-src 'none'` policy. Starting point
(replace `<api-host>`; drop it when the SPA is served from the API's origin):

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  font-src 'self'; connect-src 'self' https://<api-host>; frame-ancestors 'none'; base-uri 'self';
  form-action 'self'; object-src 'none'; upgrade-insecure-requests
```

- No `'unsafe-inline'` or `'unsafe-eval'`: the production build needs neither (the Vite dev server is not covered).
- Send `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and HSTS from the same host.
- `connect-src` must list the API origin, which must also be a registered origin of the SPA client application
  (CORS, [client-applications.md](client-applications.md)).
- Apps that sign in with OAuth (tokens in memory) need the same kind of policy; see
  `frontend/examples/consuming-app/README.md`.

## Development-only behaviour to know about

- **Plain http in Development answers 500** (T26 GAP-2): `GET http://localhost:5094/...` fails with "antiforgery ...
  SecurePolicy = Always, but the request is not an SSL request". It fails closed and is harmless. Use the https
  profile (and an https proxy target for the SPA). Production redirects http to https (307) instead.
- Development emails are `.eml` files in `DevelopmentEmail:PickupDirectory` (default `<temp>/centralauth-mail`).
- `ClientApplicationOriginOptions.RequireHttps` and the OAuth URL checks allow http only in Development.
