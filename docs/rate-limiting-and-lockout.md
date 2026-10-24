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
