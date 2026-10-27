# Threat model

Scope: Auth.Api, the Auth SPA, the Auth.Client library, and the two integration modes. This page summarises the
threats, the control for each, and the evidence that the control works. It ends with the **residual risks**: what is
known, accepted or not yet verified.

Evidence comes from:

- the test suites ([test-matrix.md](test-matrix.md), 65 architecture, 568 unit and 447 integration tests at T25);
- the live checks with curl in T26 (8 PASS, 0 gaps in the security controls).

## Assets

| Asset | Where it lives | Worst outcome |
|---|---|---|
| Passwords | Argon2id hashes in `auth.User` (m=64 MiB, t=3, p=1) | offline cracking after a database leak |
| Sessions | refresh tokens as SHA-256 hashes in `auth.RefreshToken`, cookies in the browser | account takeover |
| Signing private keys | secret store only (PEM); public JWK in `auth.SigningKey` | forged tokens accepted by every resource API |
| MFA secrets, recovery codes | AES-GCM blob (keys in the secret store), HMAC-peppered codes | second factor bypass |
| Admin privileges | `auth.Role`, `auth.UserRole`, permissions | full control of users and apps |
| Client registry | `auth.ClientApplication` (origins, redirect URIs) | codes sent to an attacker, CORS opened |
| Audit log | `auth.AuditLog` | lost accountability |

## Trust boundaries

1. **Browser and Auth.Api.** The browser is untrusted; every request is checked: Origin, antiforgery, cookies,
   rate limits.
2. **Other apps and Auth.Api.** They are trusted only as far as their registration: exact origins and redirect URIs,
   their own audience.
3. **Resource APIs and the JWKS.** Keys come from the issuer's host only, with no redirects followed.
4. **Sibling subdomains (Mode A only).** They are inside the trust boundary: they receive the access cookie and can
   set Domain cookies.
5. **Reverse proxy and Kestrel.** Forwarded headers are trusted from listed proxies only.
6. **Auth.Api and its stores.** The database holds no private key; the secret store holds no data.
7. **Administrators and users.** Permission policies apply, plus a privilege ceiling for holders who are not Admin.

## Threats and controls

| # | Threat | Control | Evidence |
|---|---|---|---|
| 1 | Credential stuffing, password guessing | Per-IP and per-account rate limits; lockout that doubles each time (5 failures, 1 min to 1 h), with a count that decays by one per quiet hour and a level reset after a quiet day; same answer for locked and unknown accounts | `SecurityScenarioApiTests` (lockout and decay), `RateLimitTests`; T26 (f): 20×401 then 5×429 |
| 2 | Account enumeration | Identical answers and timing for unknown accounts (dummy hash), identical forgot-password answer | `SignInServiceTests` (timing guard), `RegistrationApiTests.Duplicate_email_answers_are_byte_identical_to_a_new_sign_up`, T26 (f) |
| 3 | Session theft through script | Access and refresh cookies HttpOnly, Secure, `__Host-`/`__Secure-`, refresh path `/api/v1/auth`; no token in any body, URL, storage or log | T26 (a), (b), SPA bundle greps; `no-token-storage.spec.ts` |
| 4 | Stolen refresh token | Rotation on every refresh; a replay after the 10 s grace window revokes the whole family and is audited (`TokenReuse`) | `SecurityScenarioApiTests`, T26 (c), (d) |
| 5 | CSRF | SameSite cookies; Origin or Referer must be trusted; double-submit `X-XSRF-TOKEN` bound to the user; JSON only (415 for forms) | `CookieAuthTests` (Origin, Referer, XSRF), `BrowserProtectionHardeningTests`, T26 (f) |
| 6 | Cross-origin reads | CORS only for active registered origins, with credentials; no wildcard | `CookieAuthTests` (preflight), `ClientApplicationApiTests`, `CorsPolicyProviderTests`, T26 (f) |
| 7 | Forged or altered JWT | ES256/RS256 only, pinned per key; `alg=none`, HS256 confusion, wrong key, wrong `aud`/`iss`, expired, not yet valid, tampered payload, stripped signature all refused | `CookieAuthTests`, `CentralAuthClientTests`, T26 (e) |
| 8 | Token used after logout | Live-session check on Auth.Api (family and user active, 5 s cache) | `SessionLivenessTests`, `LiveSessionApiTests`; see residual risk R12 for other APIs |
| 9 | Authorization code interception or injection | PKCE S256, single-use code (1 min) bound to client, exact redirect URI and challenge; no redirect for unknown clients or URIs; `state` checked | `OAuthApiTests`, T26 (b) |
| 10 | Open redirect | The Auth SPA's `returnTo` is same-origin only: a relative app path, or the API's own OAuth authorize resume path. Absolute and cross-origin URLs are ignored (they land on `/`), so even sibling apps under the shared Domain are not redirect targets. OAuth redirect URIs are compared exactly | SPA `returnTo` tests, `OAuthApiTests.Unknown_or_inactive_clients_and_duplicate_parameters_never_redirect` |
| 11 | Privilege escalation by an admin-ish user | Permission policies on every admin route; privilege ceiling for non-Admin `roles.manage` / `users.write`; last-admin and self-change guards; the actor is re-read from the database | `AdminApiTests`, `AdminActorTests`, T26 (g) |
| 12 | MFA bypass | Second step required before any session cookie; TOTP replay window tracked; recovery codes single use and peppered; fail closed when MFA is configured wrong | `MfaApiTests` (13) |
| 13 | Clickjacking, sniffing, referrer leaks | API: CSP `default-src 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, HSTS on https | T26 (f) |
| 14 | Host header attacks | `AllowedHosts` required outside Development (no `*`) | T26 (f): a foreign Host gets 400 |
| 15 | Secrets in source or logs | No secret in committed settings (architecture test); redaction enricher for logs; email tokens in URL fragments | architecture tests, T26 (b) log greps |
| 16 | JWKS poisoning for resource APIs | JWKS on the issuer's host only, no redirects, size and key-count caps, fail closed | `JwksCacheTests`, `CentralAuthClientTests` |
| 17 | Cookie tossing in shared mode | Host-only twins expired on write; duplicate auth cookies refused (400) | `SingleLogoutApiTests.Shared_domain_mode_refuses_duplicate_auth_cookies_and_expires_the_host_only_twins`, `CookieDomainRulesTests` |
| 18 | Resource exhaustion through hashing | Bounded concurrent Argon2 operations with a queue timeout | `HashingGuardTests` |
| 19 | Audit gaps or audit growth | Catalogue-validated audit rows (no secrets); retention jobs | `AuditCoverageTests`, `RetentionPurgeTests` |

Test class names point to the test-matrix rows. The matrix lists the exact methods.

## Residual risks

These are known and either accepted, deferred, or not verifiable in this project's environment. Each has an owner
action. Severity: **M** medium, **L** low, **I** information.

### Deployment and operations

| # | Sev | Risk | What to do |
|---|---|---|---|
| R1 | M | **Behind a TLS-terminating proxy without `ForwardedHeaders:KnownProxies`, every request looks like http** (from the T09 review). `UseHttpsRedirection` loops, HSTS is never sent, and all users share the proxy's rate-limit bucket. Only single proxy IPs are accepted (no CIDR), one hop deep. | List the proxy IPs, make the proxy overwrite `X-Forwarded-*`, or set `ForwardedHeaders:Direct=true` when nothing is in front ([deployment.md](deployment.md)). |
| R2 | L | **Host filtering against load-balancer probes.** `AllowedHosts` applies to `/health` too, so a probe that sends an IP or internal name as `Host` gets 400 and the instance is marked unhealthy. | Probe with the public host name as `Host`, or add the exact probe host to `AllowedHosts`. Never `*`. |
| R3 | I | **Signing keys are added from the command line, not an admin endpoint** (T26 GAP-1, closed in T29). `signing-key add` calls `ISigningKeyRotation.AddKeyAsync`, with the overlap rule, and exits without starting the host ([setup.md](setup.md) step 3). A hand-made row from the fallback SQL recipe skips the overlap rule, but is checked at startup against the PEM, so a mismatch fails closed. | Use the command. Use the SQL recipe only for a first key when the API cannot reach the database. |
| R4 | L | **Secret names with `-` cannot be exported as bash environment variables** (T26 GAP-1). The MFA names are fixed with a hyphen (`MfaEncryptionKey-<id>`). | Kids of letters, digits and underscores. For the MFA names use User Secrets or JSON, `SecretFiles`, `env 'NAME=value'`, PowerShell, or the container or service manager ([setup.md](setup.md), "Naming rule for secrets"). |
| R5 | I | **Development plain-http requests answer 500** (T26 GAP-2): the antiforgery cookie requires SSL. It fails closed. Production redirects (307). | Use the https profile and an https proxy target for the SPA. |
| R6 | M | **No CSP ships with the SPA.** `index.html` has none, and the SPA relies on its host's headers. Tokens are not in the page, but an XSS could still act as the user. | Send the recommended CSP from the SPA's host ([deployment.md](deployment.md)). Apps in Mode B must do the same. |
| R7 | L | **No production email sender ships.** Outside Development the shipped sender refuses to send, so registration and reset fail until one is registered. | Register an `IEmailSender` for the provider (a code change). |
| R24 | M | **Database transport and storage encryption are not configured by this project** (T28 review). Every example connection string uses `TrustServerCertificate=True`, which accepts any server certificate (a man in the middle can read or change the traffic). The database holds password hashes, token hashes, MFA blobs and the audit log, so a stolen backup or disk is a full offline attack. | Production: `Encrypt=True` (mandatory or strict) with `TrustServerCertificate=False` and a certificate the API host trusts; Transparent Data Encryption and encrypted backups; least-privilege SQL login. See the [deployment.md](deployment.md) checklist. |
| R25 | L | **Rate limits and caches are per process** (T28 review). The per-IP and per-account limiters are in memory, so with N instances behind a load balancer the effective limits are N times higher, and a restart resets them. The live-session cache (5 s) and the client-application cache (CORS, redirect URIs, 30 s) are per instance too, so a change reaches each instance within its own window. The account lockout is in the database, which makes it the only control shared across instances. | Size limits per instance, prefer sticky routing for the auth paths, or put a shared limiter (gateway or WAF) in front. Treat the cache windows as the worst-case propagation delay. |

### Product and security trade-offs (accepted)

| # | Sev | Risk | Status |
|---|---|---|---|
| R8 | L | **T21b: the privilege-ceiling check runs outside the admin lock** (time of check to time of use). A concurrent role change can interleave, but no escalation beyond the actor's own privileges was found. | Logged for follow-up; not blocking. |
| R9 | L | **T21b: a non-Admin `roles.manage` holder can remove permissions from roles it does not hold.** This is an availability lever, not an escalation, and every change is audited. | Logged for follow-up; not blocking. |
| R10 | L | **T21b audit lows:** no `users.write` hierarchy beyond the ceiling; the admin rate limit is per IP, not per administrator; mass logout is a strong lever for any `users.write` holder. | Documented in [admin-api.md](admin-api.md). |
| R11 | M | **T12 MEDIUM-1:** a victim may open a verification or reset link that an attacker triggered. | Accepted by the product owner; hardened (single use, short windows, audit) ([registration-and-email-verification.md](registration-and-email-verification.md)). |
| R12 | M | **An access token stays valid for up to 15 minutes after logout or logout-all** at APIs that only check the signature. Auth.Api itself checks the session within about 5 s. Resource APIs using Auth.Client do so only if they add the optional live-session hook. | Accepted (T13 M2). Keep access tokens short; add the hook to sensitive APIs ([t22-client-extension.md](t22-client-extension.md), section 7). |
| R13 | L | **Mode A: every host under the shared Domain is trusted.** It can toss `XSRF-TOKEN` (the double submit is not bound to the session there), lock users out, and receives the access cookie. Cookie-mode APIs share one audience (confused deputy). | Hard requirement, documented ([connect-a-project.md](connect-a-project.md)). Use Mode B for anything less trusted. |
| R14 | I | **The access JWT carries `email` and `name`** (T26 GAP-3). It sits in a cookie the server can read; bearer tokens carry it to resource APIs. | Never log tokens (the redaction enricher scrubs JWTs). |
| R26 | L | **Added roles and permissions take effect at the next token mint** (T28 review). Policies read the `role` and `perm` claims in the access token, so a grant reaches a session at its next sign-in or refresh, within 15 minutes. `/me` reads the database and can show it earlier. Removals end the holders' sessions at once, so only additions wait. | Accepted: additions are not a security risk. Ask the user to sign in again when it must apply immediately ([setup.md](setup.md) step 6). |
| R27 | M | **Administrative power is concentrated, with no dual control** (T28 review). One `users.write` holder can deactivate accounts (ending their sessions) and reset their MFA; one Admin can do everything. No action needs a second approver. Guard rails exist: the privilege ceiling for holders who are not Admin, only an Admin may act on an Admin, no self-changes, the last-admin rule, a rate limit and an audit row for every change. | Keep few Admins and `users.write` holders, review the `AuditLog` for `UserDeactivated`, `MfaReset` and role changes, and verify identity out of band before an MFA reset. Dual control would be a new feature. |
| R28 | L | **An unverified sign-up keeps its Argon2id password hash in `EmailVerificationToken.PendingPasswordHash`** (T28 review), with the display name, until the link is used, or until the first retention purge run after the link expires (link lifetime 24 hours; `Retention:Interval` defaults to 1 hour). **The purge is off by default** (`Retention:Enabled` = false): without it, an unused link keeps the hash indefinitely. It is a hash, not the password, but it is personal data of someone who never finished signing up. | Accepted; mention it in the privacy notes (T23b). Enable the retention purge in production ([deployment.md](deployment.md)); it erases the payload ([audit-and-retention.md](audit-and-retention.md)). |
| R29 | L | **RequireRole does not end existing sessions at once** (T30). Turning it on, or a user losing their last role of the application without a removal (for example a role deleted on another instance), takes effect at the next refresh (within 15 minutes); an application access token already issued stays valid until it expires. `/authorize` reads the cached application view (30 s on other instances). Role removals and role deletions revoke at once. | Accepted (approved design D3). To cut a user off immediately, remove their roles (that revokes every session) or deactivate the account. |
| R15 | I | **Closed in T30.** Application roles are created, listed and deleted over the admin API (`/admin/apps/{appId}/roles`, `roles.manage`, audited), and global role names starting with `app:` are refused in code and by `CK_Role_GlobalName_NotApplicationPrefix`. | None. |

### Engineering decisions

| # | Sev | Item | Status |
|---|---|---|---|
| R16 | I | **`ConfigureAwait(false)` is not used in the server projects.** ASP.NET Core has no synchronization context, and dropping the request context risks misuse of `HttpContext`. The Auth.Client library does use it (`CentralAuthHandler`, `JwksCache`), because a host application may have a context. | Decision of 2026-10-25 (human did not object). |
| R17 | L | **The IdentityModel family is pinned to 8.23.0**, while Microsoft.Data.SqlClient 6.1.7 was built against the 7.x family. Windows-auth and SQL-auth connections are tested. Microsoft Entra ID or Key Vault SQL authentication, which use the IdentityModel code paths inside SqlClient, are **not**. | Retest before enabling Entra or Key Vault authentication for SQL ([packages.md](packages.md)). |
| R18 | I | **Privacy policy and terms pages (T23b) are pending.** They wait for the human's generator draft and need counsel review before go-live. | Open task T23b. |

### Not verified live

The T26 run used curl and could not exercise these. The automated tests cover their server side.

| # | Item | Why not | Covered by |
|---|---|---|---|
| R19 | Browser enforcement of SameSite, Secure and HttpOnly | needs a real browser | the `Set-Cookie` contract (T26 a), cookie tests |
| R20 | MFA flows end to end | needs an authenticator in a browser | `MfaApiTests` (13 HTTP tests) |
| R21 | Signing-key rotation at runtime | needs a long-running host across the overlap | `SigningKeyRotationTests`, `SigningKeyMaterialTests`, `JwksCacheTests` |
| R22 | `KnownProxies` behind a real proxy | no proxy in the test setup | `RateLimitTests.X_Forwarded_For_is_honored_only_from_a_configured_known_proxy`, `An_unconfigured_proxy_is_reported_once_as_a_warning` |
| R23 | Per-account limiter from many IPs | one source IP | `RateLimitTests` (per-account partition) |

## Signing-key maintenance command (T29)

The proposal from T27 is built.

- `dotnet Auth.Api.dll signing-key add <kid> --reference <secret name> [--algorithm ES256|RS256] [--activate-at <UTC time>]`
  runs `ISigningKeyRotation.AddKeyAsync` against the configured database and secret store, then exits.
- Exit codes: 0 when the key was added, 1 when it was not added, 2 for a usage error.
- Fix after review (T29): usage is checked before the host is built; any failure (database unreachable, a concurrent
  add of the same kid) is one line with the exception type only, and framework logs below Fatal are filtered in
  command mode, so no stack trace is printed; a `--reference` that looks like a PEM is refused; each added key writes a
  `SigningKeyAdded` audit row.
- It needs no new package and no schema change.
- `SigningKeyCommandTests` cover the parsing, the call and the error mapping.
- A run of the built dll against a throwaway database proved the rest:
  - the first key signs at once;
  - a second key without `--activate-at` is refused, naming the earliest allowed time;
  - a missing secret is reported;
  - no listener starts.
