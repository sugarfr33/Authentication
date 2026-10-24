# Sign-in, sign-out and the profile (T13)

All under `/api/v1/auth`. Tokens travel **only** in HttpOnly, Secure cookies (`__Host-access`, path `/`;
`__Secure-refresh`, path `/api/v1/auth/refresh`); no response body, URL or readable header ever carries one. Every
POST needs an allowed Origin and the `X-XSRF-TOKEN` header (browser-security.md).

| Endpoint | Auth | Body | Success | Failure |
|---|---|---|---|---|
| `POST /login` | anonymous | `{ "email", "password" }` (JSON only) | **200** `UserProfileResponse`, both cookies set, new XSRF-TOKEN | **401** ProblemDetails "Invalid email or password." |
| `POST /logout` | anonymous (works with an expired access cookie) | none | **204**, both cookies expired, new anonymous XSRF-TOKEN | - |
| `POST /logout-all` | signed in | none | **204**, every session revoked, cookies expired, new XSRF-TOKEN | **401** |
| `GET /me` | signed in | - | **200** `UserProfileResponse` | **401** (also for an inactive or deleted account) |

`UserProfileResponse`: id, email, emailVerified, displayName, mfaEnabled, roles, permissions. No hash, stamp, lockout
counters or secrets.

## Login

1. The email is normalized with the shared `EmailNormalizer` and looked up (a blank or over-long email looks up nothing).
2. The account can sign in only if it exists, is active, has a verified email, has a password (not the empty
   "no usable password" of an unverified registration), is not locked, and has no MFA (the MFA step comes with a later
   task; until then an MFA account is refused generically).
3. `IAuthTimingGuard.CheckPasswordAsync` always does **exactly one Argon2 Verify**: against the stored hash for a usable
   account, against the startup-made dummy hash otherwise. The raw length cap (1024) and the 128 code-point cap apply
   before any Verify, whatever the account. Only `VerifyAsync`/`HashAsync` go through the bounded hashing gate (busy =
   503 with Retry-After).
4. **Failure** (any reason): `ILockoutService.RegisterFailureAsync` (for an unknown email it looks up an id that
   cannot exist, so every path does a lockout round trip), then a `LoginFailed` audit row (reason `unknown`,
   `wrong_password`, `unverified`, `inactive`, `locked`, `no_password` or `mfa_not_supported`; plus a `Lockout` row when
   this failure locked the account). The answer is always the same 401 body (apart from `traceId`), with no cookies
   (tested for nine different causes).
5. **Success:** the lockout counter is reset; last login (and a rehash when the parameters changed) is saved together
   with the `LoginSucceeded` audit row and the new refresh family (IP and user agent recorded on it); an access token
   is minted for the **default audience** with `sid` = the family id. Then both cookies are written and the XSRF token
   is reissued for the new user (antiforgery tokens are user-bound).

Audit rows are staged only **after** `RegisterFailureAsync`/`ResetAsync`, because their concurrency retry clears the
change tracker (the same rule as for `RotateAsync`).

`LoginRequest.ClientId` is ignored here: client-application sign-in is the authorization-code flow (later task).

### Residual timing difference

A failure for an existing account writes the lockout UPDATE as well as the audit INSERT; an unknown email does a
lookup and the INSERT only. That is one extra small statement (well under a millisecond on the same host) next to
about 100 ms of Argon2. Locked accounts do no UPDATE either (failures while locked are not counted).

## Logout

The refresh cookie is scoped to the refresh path and never reaches `/logout`, so the session to end comes from the
**signed access cookie**: `sub` and `sid` are read after a full signature, issuer, audience and type check, with only
the lifetime check skipped (`ITokenService.ValidateIgnoringLifetimeAsync`, used for nothing else). So a user whose
access token just expired can still end the session. The family is revoked (reason `Logout`) and a `Logout` audit
row is written. Without a valid access cookie nothing is revoked, but the cookies are still expired: the browser
loses its refresh token, and the unreachable family expires on its own.

## Logout-all

Needs a valid access cookie. Revokes every refresh family of the user (reason `LogoutAll`, one UPDATE), writes a
`LogoutAll` audit row with the count, expires the cookies and reissues an anonymous XSRF token. Access tokens already
issued elsewhere stay valid until they expire (short lifetime); they can no longer be refreshed.

## Signing keys in one process

`TokenService` builds its IdentityModel keys with signature-provider caching **off**. The default factory caches
providers process-wide by key id, so a provider could keep using a key object that `SigningKeyProvider` had already
disposed (a second host in the same process, or a reload), and signing failed with ObjectDisposedException. Found by
the T13 API tests, which start a fresh host per test.

## Not done (optional item)

Audit saves are not wrapped: a database error while writing an audit row still fails the request (500, generic). Since
that happens on every path alike, it reveals nothing; making audit best-effort needs a logger in Auth.Services and is
left for the audit/observability task.
