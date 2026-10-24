# Rate limiting, lockout and hashing capacity (T11)

## Rate limiting (Auth.Api)

Three steps, in this order, on the auth paths (framework limiter, no package):

1. **Per client IP** (`UseRateLimiter`, the global limiter): a fixed window per auth operation. It counts the
   request **before** the body is read, so slow or oversized bodies are counted too.
2. **Body cap and account key** (`AccountKeyMiddleware`): every POST to a rate-limited path is capped at
   `MaxAccountBodyBytes` (16 KB). The server's `MaxRequestBodySize` is lowered for the request and the body is read
   into memory up to that size, so anything larger (with or without Content-Length) gets **413** and never reaches the
   endpoint, and nothing is buffered to disk. For kinds with a per-account rule, the email is then read exactly like
   the endpoint's System.Text.Json binder: UTF-8 BOM skipped, depth 64, case-insensitive name, last value wins. A
   declared non-utf-8 charset gets **415**. Ambiguous or unparsable bodies (duplicated, non-string or blank email,
   malformed JSON, invalid UTF-8) all share one constant bucket, so parsing tricks cannot escape the limit. A body
   the server itself cannot read keeps the server's status (408 too slow, 400 bad framing) and is logged as a warning;
   413 is only for a real overflow. Rate-limited endpoints bind JSON bodies only, never forms (tested).
3. **Per account** (`AccountRateLimitMiddleware`): a fixed window per normalized email. There is one normalizer,
   `EmailNormalizer` (Auth.Contracts: trimmed, upper case, at most 256 characters), used for the rate-limit key,
   `User.NormalizedEmail` and every lookup by email.

Operations are matched **by request path** (`RateLimiting:Paths`), so the limits apply to the T12/T13 endpoints as
soon as they exist at these paths:

| Kind | Path | Per IP | Per account |
|---|---|---|---|
| Login | `/api/v1/auth/login` | 20 / 1 min | 10 / 15 min |
| Refresh | `/api/v1/auth/refresh` | 60 / 1 min | - |
| Register | `/api/v1/auth/register` | 10 / 1 h | 3 / 1 h |
| ForgotPassword | `/api/v1/auth/forgot-password` | 10 / 15 min | 3 / 15 min |
| ResetPassword | `/api/v1/auth/reset-password` | 10 / 15 min | - |
| VerifyEmail | `/api/v1/auth/verify-email` | 30 / 15 min | - |

All values can be changed under `RateLimiting:Policies:<Kind>:PerIp|PerAccount:PermitLimit|Window`. Other paths are not
limited. OPTIONS (preflight) is never counted. A rejection is **429** ProblemDetails with `Retry-After` (seconds until
the window resets). The account limit applies whether or not the account exists, so it reveals nothing.

### Client IP and proxies

The IP partition uses `Connection.RemoteIpAddress`. `X-Forwarded-For`/`X-Forwarded-Proto` are honored **only** from
the proxies listed in `ForwardedHeaders:KnownProxies` (ForwardLimit 1). With none configured (the default) the
headers are ignored, so a client cannot spoof its partition. Configure the reverse proxy addresses in production.

If no proxies are configured but a request arrives from a loopback or private peer **with** X-Forwarded-For, the API
is probably behind an unconfigured proxy, and every user would share one IP bucket. Outside Development this logs one
warning per app instance (`ProxyMisconfigurationDetector`). Set `ForwardedHeaders:Direct=true` to declare that there
really is no proxy and silence it.

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

`CheckPasswordAsync(password, storedHash, accountUsable, ct)` costs **exactly one Argon2 Verify** on every path. For an unknown,
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
- **Body reading.** (Audit fix) The per-IP limit now counts a request before its body is read, and the body is capped
  at 16 KB in memory (413 above). Slow senders are still bounded by Kestrel's `MinRequestBodyDataRate` (default 240
  bytes/s after a 5 s grace); keep it at the default or tighter.
- **IPv6.** Per-IP limits partition IPv6 clients by /64 (one subscriber typically holds a whole /64), IPv4 per
  address, and IPv4-mapped IPv6 as IPv4.
- **Hashing capacity.** Waiting for a hashing slot is asynchronous (no thread is held while queued), and Argon2 runs
  on a worker. The timing guard's dummy hash is created at startup (and otherwise on first need); a failure (e.g.
  busy) is not cached, so the next request simply tries again. A failed warm-up is logged as a warning and never
  stops the host.
- **Lockout window and decay (audit LOW-4, for T17).** `FailedLoginCount` never decays with time and the lockout level
  resets only on success. A failure window (reset the count after N quiet minutes) and level decay after a quiet period
  are on the T17 list, together with the unlock-by-email-link mitigation.
- **Timing residuals for T13 (audit LOW-5).** (i) The dummy hash is now created at startup by a background warm-up,
  so the first unknown-account sign-in costs no extra Hash. (ii) `RegisterFailureAsync` writes to the database only
  for existing accounts; T13 should do an equivalent round trip for unknown accounts and keep the locked and
  wrong-password responses byte-identical. (iii) A stored hash that cannot be parsed returns Failed without Argon2
  work; such rows should not exist, but T13 can verify against the dummy hash in that case.
- **Capacity settings.** `PasswordHashing:MaxConcurrentOperations` is limited to 1..64 (64 is about 4 GiB of peak
  Argon2 memory). Waiting for a slot is bounded by the 5 s queue timeout. Request paths must use `HashAsync` and
  `VerifyAsync` only; the sync methods block a thread while queued. A client that disconnects while queued is
  answered quietly (status 499, no error log).
