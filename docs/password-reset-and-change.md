# Forgot, reset and change password (T14)

All under `/api/v1/auth`, JSON bodies only, behind the origin check, the antiforgery token, the per-IP limits and the
16 KB body cap (forgot-password also the per-account limit, keyed by the shared `EmailNormalizer`).

| Endpoint | Auth | Body | Success | Failure |
|---|---|---|---|---|
| `POST /forgot-password` | anonymous | `{ "email" }` | **202** `{ "message": "If an account can reset ..." }`, identical for every email | **400** ValidationProblem only for a malformed email (decided without the database) |
| `POST /reset-password` | anonymous | `{ "token", "newPassword" }` | **204** | **400** "The reset link is invalid or has expired."; **400** ValidationProblem (`newPassword`) for a rejected password |
| `POST /change-password` | signed in | `{ "currentPassword", "newPassword" }` | **204**, cookies expired, anonymous XSRF reissued | **400** "The current password is incorrect."; **400** ValidationProblem (`newPassword`); **401** |

## Forgot password: no enumeration

Every well-formed request gets the same 202 with a byte-identical body (tested for verified, unverified, inactive and
unknown addresses), after the same work: one lookup, one save, one email, no hashing.

| | Active, verified | Unverified (no usable password) | Inactive | Unknown |
|---|---|---|---|---|
| Save | reset link + `PasswordResetRequested` audit | audit | audit | audit (no user id) |
| Email | reset link | "finish signing up first" notice | "account disabled" notice | "no account for this address" notice |

The audit detail records the outcome (`sent`, `unverified`, `inactive`, `unknown`). Earlier unused links stay valid until
they expire or one link is redeemed (redeeming retires all of them), so a request never needs an extra UPDATE. The mail
volume a third party can cause is bounded by the per-account limit (3 per address per 15 min) and the per-IP limit.

An **unverified account is never made usable** by this flow: it gets no link, and even a reset link that somehow
exists for an unverified account sets the password but never sets `EmailVerified` (tested). Signing in still requires a
verified email (T13).

## Reset link

- 256 bits from `ITokenGenerator`, base64url; only its **SHA-256** is stored in `auth.PasswordResetToken` with the
  requester's IP. Expires after `AccountEmail:ResetTokenLifetime` (default **15 min**, allowed 5 to 60).
- The link is `AccountEmail:ResetPasswordUrl` + `#token=...`: the token is in the URL fragment, so it never reaches a
  server log or a Referer header; the page posts it to `/reset-password`.
- Order of checks: link (unknown, used, expired, owner missing or inactive: the one generic 400), then the T06 policy
  for the new password with the owner's email (a rejected password does **not** spend the link), then one `HashAsync`,
  then the transaction.
- **Single use:** a conditional UPDATE marks the link used inside a ReadCommitted transaction; of 16 parallel
  redemptions exactly one succeeds (tested). A RowVersion conflict on the user retries once with a clean tracker.

## What a new password ends (reset and change alike)

In the same transaction: new Argon2 hash, **new SecurityStamp**, lockout cleared (`FailedLoginCount`, `LockoutEndUtc`,
`LockoutLevel`), **every refresh family revoked** (reason `PasswordChange`, the current session included), every reset
link retired, and every email-verification link retired with its pending sign-up password and display name erased. Then
a "your password was changed" notice is emailed. That notice is **best effort** (review T14): the change is already
committed (and a reset link already spent), so if the sender fails the answer is still 204 (change still expires the
cookies), and the API logs a warning with the exception type only. Cancellation is not swallowed. Tested with a failing
sender for both flows. The forgot-password email is not best effort: it is the purpose of that request and fails the
same way on every path. Tested with two browsers: both sessions are revoked, the old password
fails and the new one signs in.

Change password also expires the cookies of the browser that made the change and reissues an anonymous XSRF token:
the user signs in again with the new password (decision: no session survives a password change).

## Change password

- Needs a signed-in user, the antiforgery token (400 without it, tested) and the per-IP limit (`ChangePassword`, 10 per
  15 min).
- The new password is checked against the T06 policy first (no Argon2 work for a rejected one).
- The current password goes through `IAuthTimingGuard`: exactly one Verify, raw 1024 and 128 code-point caps first, a
  dummy hash when the account cannot sign in (inactive, unverified, locked, no password). Any failure is the one
  "current password is incorrect" answer and counts toward the account lockout (a stolen session cannot brute-force the
  password).

## Audit

`PasswordResetRequested` (outcome), `PasswordReset`, `PasswordChanged`, and the new `PasswordResetFailed` (reason:
`malformed`, `unknown`, `used`, `expired`, `unknown_user`, `inactive`, `policy`) and `PasswordChangeFailed` (reason:
`policy`, `wrong_password`, `unusable_account`). Never a token or a password; a user id only when the account exists.
No token or password reaches any log (tested).

## Residual notes (security audit T14; also for the T27 threat model)

- **Mail volume (LOW-2).** A third party can use up an address's forgot-password budget (3 per 15 min per normalized
  email), delaying the owner's own request for up to 15 minutes. Plus-address variants (`a+1@x`, `a+2@x`) are separate
  keys, so one IP can make a single mailbox receive up to its per-IP limit (10 per 15 min) of notices. Bounded and
  accepted; a later option is a per-mailbox key that ignores the `+tag`.
- **Lockout through a stolen session (LOW-3).** Failed change-password attempts count toward the login lockout, so
  someone holding a live stolen session could lock the owner out of signing in. It needs a valid session first; a reset
  (mailbox control) clears the lockout. Accepted.
- **Inline email and small work differences (LOW-4).** The sent path adds one link INSERT and a SHA-256 in the same
  save; the SMTP call is awaited inline on every path and dominates. A background mail queue (see the T12 deployment
  notes) would remove the residual timing and the request-time cost of slow providers.
- **Expiry inside the UPDATE (INFO-2).** The link's expiry is checked just before the conditional UPDATE, not inside it,
  so a link can be redeemed in the sub-second between the two. Accepted (the shared single-use repository serves tables
  without an expiry column).
- **Access tokens after a password change (INFO-1, closed before T16).** A change or reset revokes every session, and
  the live-session check (sign-in-and-sessions.md) then refuses the old access cookies within its cache time (5 s).

## Not done

Optional audit-save wrapping (so a database error while auditing cannot change an answer) is not done, as in T13: it
needs a logger in Auth.Services and the failure would be the same on every path.
