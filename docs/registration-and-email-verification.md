# Registration and email verification (T12)

## Endpoints

Both are anonymous POSTs under `/api/v1/auth` with JSON bodies only (a form body gets 415). Like every POST they need an
allowed Origin and the `X-XSRF-TOKEN` header (see browser-security.md), and they go through the per-IP limit, the
16 KB body cap and, for register, the per-account limit (see rate-limiting-and-lockout.md).

| Endpoint | Body | Success | Failure |
|---|---|---|---|
| `POST /register` | `{ "email", "password", "displayName" }` | **202** `{ "message": "Check your inbox: ..." }` | **400** ValidationProblem (`errors` keyed `email`, `password`, `displayName`); malformed JSON 400 ProblemDetails |
| `POST /verify-email` | `{ "token" }` | **204** | **400** ProblemDetails "The verification link is invalid or has expired." |

## Validation (hand-written, no package)

FluentValidation is on the T00 planned list but was not added: `RegisterRequestValidator` (Auth.Services) does the
same checks with no new dependency.

- **email:** required. After trimming it must have exactly one `@`, a local part of 1-64 characters, a dotted domain
  without empty labels, no whitespace or control characters, at most 256 characters, and be a bare address
  (`MailAddress`, no display name).
- **password:** the T06 policy (12 to 128 code points after NFKC, not a common password, not the email local part).
  A raw value over 1024 characters is refused before the policy normalizes (copies) it.
- **displayName:** required after trimming, at most 128 characters, no control characters.

Validation never reads the database, so its answer is the same for new and existing emails.

## Duplicate email does not reveal existence

Every valid request gets the same **202**, content type and byte-identical body (tested). The work done is the same
too (tested by counting, not by timing):

| | New email | Existing, unverified | Existing, verified (or inactive) |
|---|---|---|---|
| Argon2 hash (async, through the bounded gate) | 1 | 1 (discarded) | 1 (discarded) |
| Lookup by normalized email | 1 | 1 | 1 |
| Save | user (no usable password) + link + audit | new link + audit | audit |
| Email | verification link | fresh verification link | "your account already exists" notice |

- Re-registering an unverified address sends one more link, so a person who lost the first email can simply sign
  up again. Earlier links stay valid and keep their own password (see below). A duplicate request never changes the
  User row.
- Two concurrent sign-ups with one email: the unique index on `NormalizedEmail` rejects the second insert, which then
  follows the duplicate path (same answer).
- The per-account rate limit counts the email whether or not it exists.

## Verification token

- 256 bits from the OS CSPRNG, base64url (43 characters), from `ITokenGenerator`. Only its **SHA-256** is stored
  (`auth.EmailVerificationToken.TokenHash`, unique index); the raw value exists only in the email.
- **Expires** after `AccountEmail:VerificationTokenLifetime` (default 24 h, allowed 1 min to 7 days).
- **Single use:** redeeming runs in one transaction: a conditional UPDATE marks the token used only if it is still
  unused (concurrent redemptions: exactly one succeeds, tested with 16 parallel calls). Then the link's pending
  password hash and display name are copied to the User row, `EmailVerified` is set, the `SecurityStamp` rotates,
  every refresh token of the user is revoked (reason PasswordChange), the user's other unused links are retired, and
  an `EmailVerified` audit row is written.
- A link of an account that is already verified fails, so a leftover link can never change a verified account.
- **No secret left behind (audit LOW-1):** the same conditional UPDATE that marks a link used or retires it sets its
  `PendingPasswordHash` and `PendingDisplayName` to NULL. After a verification, the account's other links hold no
  hash either. Links that simply expire unused keep theirs until a purge job removes expired rows and long-unverified
  accounts (planned with the T17 cleanup work).
- Unknown, used, expired, malformed or over-long tokens, and tokens of inactive accounts, all give the same 400.
- The link is `AccountEmail:VerifyEmailUrl` + `#token=...`. The token is in the URL **fragment**, so it never
  reaches a server log, a proxy or a Referer header; the front-end page posts it to `/verify-email`.

## Email sender (`IEmailSender`, Auth.Services)

- **Development:** `PickupDirectoryEmailSender` writes each message as a `.eml` file to
  `DevelopmentEmail:PickupDirectory` (default `%TEMP%/centralauth-mail`). The log line names only the subject and the
  file: never the recipient, the body or the token.
- **Other environments:** until a real provider is registered, `UnconfiguredEmailSender` logs an error and refuses
  (the request fails with 500). New and duplicate sign-ups both send exactly one email, so this fails them alike and
  reveals nothing. **Deployment requirement:** register a real `IEmailSender` before going live.
- Registration sends the email after the save. If sending fails, the account exists without a delivered link;
  registering again sends a fresh one.

### Deployment notes (audit LOW-3)

- Register a real `IEmailSender` before going live; the default outside Development refuses to send.
- The real sender must behave **the same for every recipient** from the caller's point of view: enqueue the message
  (outbox table or queue) and deliver it after the response, so provider latency, bounces or rejected recipients can
  never make a new address answer differently (status or timing) from an existing one. Do not send SMTP inline.
- Treat `To` as data (it is validated, and the subject is constant), and never log the body: it holds the one-time link.

## Audit

Through `IAuditLogRepository`, each with IP, user agent and trace id:

- `Registered` (detail `{"outcome":"created"}` or `{"outcome":"duplicate"}`, with the account's user id).
- `RegistrationRejected` (audit LOW-4): detail `{"fields":[...]}` with the failing field names only, never the values;
  no user id (validation does not read the database).
- `EmailVerified`.
- `EmailVerificationFailed` (audit LOW-4): detail `{"reason":"..."}`, one of `malformed`, `unknown`, `used`, `expired`,
  `no_pending_password`, `unknown_user`, `inactive`, `already_verified`, with the link's user id when the link
  exists. Written in its own save after the failed attempt rolled back. The HTTP answer stays the one generic 400.

No token, password or hash is written to the audit log or to any log. The audit log names the requester IP for
attempts against existing accounts, so audit reads must stay restricted to support and security staff.

### Mail volume (audit LOW-2)

Each register request for an unverified address sends one link and each for a verified one sends a notice, so a third
party can make an address receive mail. This is bounded by the per-account register limit (3 per email per hour,
`RateLimiting:Policies:Register:PerAccount`) plus the per-IP limit; the same limit can also keep the real owner from
signing up for up to an hour. A "one mail per account per 5 minutes" throttle was considered and **not** built: skipping
the email for some duplicates would make that path do less work than a new sign-up (an observable difference while
emails are sent inline), which is the uniformity this endpoint must keep. Once the queued sender above exists, the
throttle can live in the queue (drop or merge repeats) without touching the request path.

## No account pre-hijacking (review HIGH-1)

The attack: someone registers the victim's email first, with a password they know, and waits for the victim to
confirm the address. The defence is that a password becomes usable **only** through the link its own registration
produced:

- Registration never writes a password to the User row. A new account has `PasswordHash = ''` (no usable password),
  which no hash string matches: the T13 sign-in check verifies a dummy hash instead and returns the same generic
  failure as for an unknown email.
- The registration's Argon2 hash and display name are stored on its own link (`auth.EmailVerificationToken`
  columns `PendingPasswordHash` nvarchar(512) and `PendingDisplayName` nvarchar(128), added by migration
  `EmailVerificationPendingRegistration`; nullable, and a link without a pending password cannot be redeemed).
- Redeeming a link activates that link's password only, rotates the security stamp, revokes all refresh tokens and
  retires the other links. Later registrations add links but never change an earlier link's password.

Tested both ways round with the sign-in check: attacker first then victim, and victim first then attacker. In both,
after the victim's link is redeemed the victim's password signs in and the attacker's does not.

**Residual risk (audit MEDIUM-1, accepted by the product owner for now):** the victim's inbox may hold a link produced
by the attacker's registration. If the victim opens THAT link (and not their own) before any other, the attacker's
password is activated. Mitigations in place:

- Every link email (first or repeated sign-up, one template) names the time of the sign-up it confirms, says that
  opening it activates the password chosen in that sign-up, and tells the reader not to open it unless they made that
  sign-up, and to open only the matching one when several arrive.
- T13 refuses sign-in for unverified accounts with the generic failure; the T14 password reset is the recovery path
  (it rotates the stamp and revokes sessions).

Not done, by decision: asking for the sign-up password on verify-email (would close it completely; changes
VerifyEmailRequest and the front end).

## Not in T12

Signing in is T13. It must decide how to treat `EmailVerified = false` (`AuthError.EmailNotVerified` exists), and keep
that answer from revealing which emails exist.
