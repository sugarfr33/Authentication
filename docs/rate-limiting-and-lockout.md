# Rate limiting, lockout and hashing capacity (T11)

## Rate limiting (Auth.Api)

The framework rate limiter (`Microsoft.AspNetCore.RateLimiting`, no package) runs one **global, chained** limiter:

1. **Per client IP**: a fixed window for each auth operation.
2. **Per account**: a fixed window per normalized email (trimmed, upper case, like `User.NormalizedEmail`).
   `AccountKeyMiddleware` reads at most `MaxAccountBodyBytes` (16 KB) of a JSON body to find a top-level `email`,
   then rewinds it for the endpoint. A larger, chunked-beyond-limit or non-JSON body gets no account key and is still
   IP-limited. Nothing beyond the limit is held in memory by this step.

Operations are matched **by request path** (`RateLimiting:Paths`), so the limits apply to the T12/T13 endpoints as
soon as they exist at these paths:

| Kind | Path | Per IP | Per account |
|---|---|---|---|
| Login | `/api/v1/auth/login` | 20 / 1 min | 10 / 15 min |
| Refresh | `/api/v1/auth/refresh` | 60 / 1 min | - |
| Register | `/api/v1/auth/register` | 10 / 1 h | 3 / 1 h |
| ForgotPassword | `/api/v1/auth/forgot-password` | 10 / 15 min | 3 / 15 min |
| ResetPassword | `/api/v1/auth/reset-password` | 10 / 15 min | - |

All values can be changed under `RateLimiting:Policies:<Kind>:PerIp|PerAccount:PermitLimit|Window`. Other paths are not
limited. OPTIONS (preflight) is never counted. A rejection is **429** ProblemDetails with `Retry-After` (seconds until
the window resets). The account limit applies whether or not the account exists, so it reveals nothing.

### Client IP and proxies

The IP partition uses `Connection.RemoteIpAddress`. `X-Forwarded-For`/`X-Forwarded-Proto` are honored **only** from
the proxies listed in `ForwardedHeaders:KnownProxies` (ForwardLimit 1). With none configured (the default) the
headers are ignored, so a client cannot spoof its partition. Configure the reverse proxy addresses in production.

## Account lockout (Auth.Services `ILockoutService`)

Persisted on the User row (`FailedLoginCount`, `LockoutEndUtc`, `LockoutLevel`):

- `FailuresBeforeLockout` (5) consecutive failures lock the account for `BaseLockout * 2^(level-1)` (1, 2, 4, 8 ... min),
  capped at `MaxLockout` (1 h). The counter restarts after each lock; failures while locked are not counted.
- `ResetAsync` (successful sign-in) clears the counter, the lock and the backoff level.
- Writes use the User RowVersion with a bounded retry, so concurrent failures are never lost (tested in parallel).
- `RegisterFailureAsync` returns `AccountLockedOut` when this failure caused the lock: the hook T17 logs as Lockout.
- T13 must answer a locked account exactly like a wrong password (see the timing guard).

Settings: section `Lockout` (`FailuresBeforeLockout`, `BaseLockout`, `MaxLockout`).

## Anti-enumeration (`IAuthTimingGuard`)

`CheckPassword(password, storedHash, accountUsable)` costs **exactly one Argon2 Verify** on every path. For an unknown,
inactive or locked account it verifies against a dummy hash made with the current parameters. Every failure is the same
`CredentialCheck.Invalid`. The 128-code-point maximum is enforced before Verify, independent of the account. Tests count
hasher calls; they do not measure wall-clock time.

## Hashing capacity

Every hash or verify goes through `BoundedPasswordHasher`: at most `PasswordHashing:MaxConcurrentOperations` (default
half the processors, 1 to 16) Argon2 operations at once, which is about 64 MiB each. A caller waits up to `QueueTimeout`
(5 s). After that, `PasswordHashingBusyException` becomes **503** ProblemDetails with `Retry-After: 1`, logged as a
warning, instead of the process running out of memory.

## Known trade-offs and residual risks (T11 review)

- **Targeted lockout (denial of a known victim's login).** Anyone who knows an email can drive that account into
  lockout, and the per-account rate limit, by submitting wrong passwords. The lockout level does **not** decay over
  time; only a successful sign-in resets it, so repeated attacks keep the backoff at its 1 h cap. This is the usual price
  of per-account protection against online guessing. **Future mitigation:** let the real owner bypass or clear the lock,
  e.g. an unlock link sent by email, or a trusted-device cookie that exempts known devices from the lock.
- **Ambiguous email fields.** The account key mirrors System.Text.Json web-default binding: the property name matches
  case-insensitively (`email`, `Email`, `EMAIL`, ...) and the last value wins. A body whose email field is duplicated,
  non-string or empty is put in one shared constant bucket, so such tricks cannot escape the per-account limit. The
  field name is the shared constant `AuthRequestFields.Email` (Auth.Contracts), also used by the request DTOs.
- **Loopback origins.** In production, http is accepted only for loopback origins (`localhost`, `127.0.0.1`, `[::1]`)
  when they are registered. Keep localhost entries out of production ClientApplication rows: any process on the user's
  machine could use them.
- **Body buffering before the IP throttle.** `AccountKeyMiddleware` runs before the limiter, so it reads up to
  `MaxAccountBodyBytes` (16 KB) of a request even when the IP limit will reject it. This is bounded per request; slow
  senders are bounded by Kestrel's `MinRequestBodyDataRate` (default 240 bytes/s after a 5 s grace), and the request
  body size by `MaxRequestBodySize`. Keep both at their defaults or tighter.
- **IPv6.** Per-IP limits partition IPv6 clients by /64 (one subscriber typically holds a whole /64), IPv4 per
  address, and IPv4-mapped IPv6 as IPv4.
- **Hashing capacity.** Waiting for a hashing slot is asynchronous (no thread is held while queued), and Argon2 runs
  on a worker. The dummy hash used by the timing guard is created on first need; a failure (e.g. busy) is not cached,
  so the next request simply tries again.
