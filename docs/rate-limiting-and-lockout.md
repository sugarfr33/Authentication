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

Operations are matched **by request path** (`RateLimiting:Paths`). Register and verify-email (T12), login (T13) and
forgot, reset and change password (T14), refresh and the sessions routes (T15) are live at these paths.
`RateLimiting:PathPrefixes` matches routes with an id by prefix (`/api/v1/auth/sessions` and anything below it). Logout,
logout-all and /me are not rate limited (they need the antiforgery token, and logout-all and /me also a session):

| Kind | Path | Per IP | Per account |
|---|---|---|---|
| Login | `/api/v1/auth/login` | 20 / 1 min | 10 / 15 min |
| Refresh | `/api/v1/auth/refresh` | 60 / 1 min | - |
| Register | `/api/v1/auth/register` | 10 / 1 h | 3 / 1 h |
| ForgotPassword | `/api/v1/auth/forgot-password` | 10 / 15 min | 3 / 15 min |
| ResetPassword | `/api/v1/auth/reset-password` | 10 / 15 min | - |
| VerifyEmail | `/api/v1/auth/verify-email` | 30 / 15 min | - |
| ChangePassword | `/api/v1/auth/change-password` | 10 / 15 min | - (signed in; wrong current passwords count toward lockout) |
| Sessions | `/api/v1/auth/sessions` and `/api/v1/auth/sessions/{id}` (prefix) | 60 / 1 min | - (signed in) |

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
- **Failure decay (T17, paced by the T17 audit).** The counter decays by **one per full `FailureWindow`** since the
  last failure. The default and minimum window is `MaxLockout` (1 h). It never resets to zero, so pacing cannot dodge
  the lock. Each counted failure sets `UpdatedUtc`, which is the "last failure" time (no new column).
- **Level decay (T17).** The backoff level is forgotten once `LevelDecayAfter` (24 h, at least `MaxLockout`) has passed
  since the end of the last lock (`LockoutEndUtc` is kept after it expires), so the next lock starts at 1 minute again.
- Both are tested with a fake clock, including mutation checks (disabling either fails its test).
- Writes use the User RowVersion with a bounded retry, so concurrent failures are never lost (tested in parallel).
- `RegisterFailureAsync` returns `AccountLockedOut` when this failure caused the lock: the hook T17 logs as Lockout.
- Login (T13) answers a locked account exactly like a wrong password, after the same single Verify (see sign-in-and-sessions.md).

Settings: section `Lockout` (`FailuresBeforeLockout`, `BaseLockout`, `MaxLockout`, `FailureWindow`, `LevelDecayAfter`).
`FailureWindow` or `LevelDecayAfter` below `MaxLockout` stop the app at startup (the options are validated in
Program.cs, not on first login).

### Guesses per account per day (defaults: 5 failures, lock 1 min doubling to 1 h, window 1 h)

| Attacker strategy | Before T17 | T17 first version (15 min reset) | Now (decay by 1 per hour) |
|---|---|---|---|
| Trigger locks back to back | about 120 (5 per lock at the 1 h cap) | about 120 | about 120 |
| Stay just under the threshold | none possible (failures never decayed) | 4 per 15 min = 384 | 4 at once, then about 1 per hour: 27 the first day, 24 a day after |

- The **per-account rate limiter** (Login, 10 per 15 min, keyed on the submitted email) caps any strategy at 960 a
  day, independent of the lockout.
- The **password policy** (length, common-password list) makes the remaining online guessing budget useless against
  real passwords.
- The **level decay** (24 h) only helps an attacker who stays away for a day, which resets them to the first step
  and also gives the owner a quiet day.

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
  lockout, and the per-account rate limit, by submitting wrong passwords. Since T17 the level decays after a quiet day,
  but an attacker who keeps going keeps the backoff at its 1 h cap. This is the usual price of per-account protection
  against online guessing. **Unlock by email (deferred, T17):** the real owner can already clear a lock with "Forgot
  password": a successful reset clears the counter, the lock and the level. A dedicated unlock link would need its own
  token purpose (a schema change, or overloading the reset table) and, sent on every lock, would let anyone trigger
  emails to a victim; it is deferred until there is a decision on both. A trusted-device cookie remains an option.
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
- **Lockout window and decay (audit LOW-4).** Done in T17 (see "Account lockout"); unlock-by-email deferred (above).
- **Timing residuals for T13 (audit LOW-5).** (i) The dummy hash is now created at startup by a background warm-up,
  so the first unknown-account sign-in costs no extra Hash. (ii) `RegisterFailureAsync` writes to the database only
  for existing accounts; T13 should do an equivalent round trip for unknown accounts and keep the locked and
  wrong-password responses byte-identical. (iii) A stored hash that cannot be parsed returns Failed without Argon2
  work; such rows should not exist, but T13 can verify against the dummy hash in that case.
  **T13 status:** (ii) done: an unknown email also does a lockout round trip (a lookup) and the same audit insert, and
  every failure answer is identical (tested); the residual is the lockout UPDATE for existing accounts
  (sign-in-and-sessions.md). (iii) the empty "no usable password" hash of unverified registrations is refused before
  the guard, so it verifies the dummy hash; only a corrupted, non-empty hash would skip Argon2.
- **Capacity settings.** `PasswordHashing:MaxConcurrentOperations` is limited to 1..64 (64 is about 4 GiB of peak
  Argon2 memory). Waiting for a slot is bounded by the 5 s queue timeout. Request paths must use `HashAsync` and
  `VerifyAsync` only; the sync methods block a thread while queued. A client that disconnects while queued is
  answered quietly (status 499, no error log).
