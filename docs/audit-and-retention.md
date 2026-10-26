# Audit logging, log scrubbing and retention (T17)

## Writing audit rows: `IAuditService`

Every audit row goes through `IAuditService` (Auth.Services/Audit). Nothing else writes `auth.AuditLog`: a unit test
fails if any other Services type depends on `IAuditLogRepository`.

- **Typed events.** Rows are built only by the `AuditEvents` factories, one per written event type and named after it,
  with typed arguments (user id, reason word, counts, ids, times). There is no way to pass a free-form detail string.
- **Catalogue.** `AuditCatalogue.Events` lists every `AuditEventType`: the allowed detail keys, the volume (normal or
  high) and whether it is reserved. Reserved types belong to features that do not exist yet (MFA, OAuth codes,
  signing-key rotation events) and have no factory; a unit test checks both directions.
- **Central redaction of the detail JSON.**
  - Only the catalogue's keys for that type are written; any other key is dropped.
  - Values are numbers, booleans, GUIDs, UTC times, or words from `AuditCatalogue.Words`: the fixed reasons,
    outcomes, field names, system role names and sources. Any other string is written as `"[redacted]"`.
  - So a password, token, hash or free text can never be persisted, even if a caller passed one by mistake. Unit tests
    plant passwords, refresh tokens, JWTs and Argon2 hashes.
- **Three ways to write:**
  - `StageAsync`: the row is saved with the caller's own change, all or nothing (login, lockout, password set,
    registration, role changes). Stage only after any call that may clear the change tracker (rotation, lockout
    retries).
  - `WriteAsync`: the row has its own save, and a failure throws. Used on failure paths (failed verification, reset or
    change), where nothing has succeeded yet.
  - `TryWriteAsync`: best effort, used after a change has already succeeded (logout, logout-all, session revoke,
    refresh, reuse, session cap).
    - A failure never changes the HTTP answer.
    - It is reported to `IAuditFailureReporter`. The API's `AuditFailureLog` logs at most one warning per minute,
      with the count, the latest event type and the exception type.
    - The user id is kept only if the account still exists (AuditLog has a foreign key to User).

### Event coverage

`AuditCoverageTests` walks **every** `AuditEventType`:

- A written type must name a test that asserts its persisted row. The method must exist and be a test.
- A reserved type must not be mapped.

The main test is `AuditTrailApiTests.Every_account_event_is_persisted_and_no_row_or_log_line_holds_a_secret`. It drives
one account through its whole life over HTTP:

- rejected and accepted sign-up, verification, a forged verification link;
- a wrong and a right password, a refresh;
- a change-password with a wrong current password, one with a weak new password, and a real change;
- forgot-password, a forged reset link, and a real reset.

It then checks that every expected row exists. It also checks that no audit column (detail, IP, user agent,
correlation id) and no captured log line holds any planted secret: passwords, link tokens, cookies, the password hash.

### Event catalogue

| Event | Detail keys | Volume |
|---|---|---|
| Registered | outcome (created) | normal |
| RegistrationDuplicate | none (a sign-up for an existing account) | **high** |
| EmailVerified | none | normal |
| EmailVerificationFailed | reason | **high** |
| RegistrationRejected | fields (names only) | **high** |
| LoginSucceeded | none | normal |
| LoginFailed | reason | **high** |
| Lockout | until, level | normal |
| Logout, LogoutAll | revoked (count) | normal |
| TokenRefreshed | none | **high** |
| TokenReuse | revoked (count) | normal |
| RefreshRejected | reason | **high** |
| SessionRevoked | session, reason (session_cap when the server ended it) | normal |
| PasswordResetRequested | outcome | **high** (anyone can cause it, also for unknown emails) |
| PasswordReset, PasswordChanged | none | normal |
| PasswordResetFailed, PasswordChangeFailed | reason | normal |
| RoleAssigned | role, source (bootstrap, backfill) | normal |
| RoleRemoved | role (id) | normal |
| RolePermissionRemoved | role, permission (ids) | normal |
| AppCreated | app (id), source (registry, bootstrap) | normal |
| AppUpdated | app (id), active, revoked (count, when an audience change ended its sessions) | normal |
| AppDeactivated | app (id), revoked (count) | normal |
| AuthorizationCodeIssued | app (id) | normal |
| AuthorizationCodeRedeemed | app (id), session (id) | normal |
| AuthorizationCodeRejected | app (id, when known), reason | **high** |
| SingleLogout | cause (logout, logout_all, session_revoked, token_reuse, password_change, application_logout), revoked (count), app (id, RP-initiated only) | normal |
| MfaEnrollmentStarted | none | normal |
| MfaEnabled | action (enrolled, regenerated) | normal |
| MfaDisabled | action (disabled, reset) | normal |
| MfaVerified | none | normal |
| MfaFailed | reason (wrong_code, wrong_recovery_code, replayed, locked, bad_challenge without user id, wrong_password, conflict) | **high** |
| MfaRecoveryCodeUsed | none | normal |
| SigningKeyRotated | reserved | |

**TokenRefreshed decision:** it is kept, with no sampling. It writes about one row per 15 minutes per active session. It
is high-volume, so it gets the short retention below. Sampling would hide the refresh history of a stolen session, and
dropping the row would lose the only record of when a session was used.

## Reading audit rows (T21b: `GET /api/v1/admin/audit`)

The read endpoint is described in docs/admin-api.md. It follows these rules:

- It must require the `audit.read` permission policy (`AuthPolicies.AuditRead`), never only "signed in".
- Rows must never be shown to the user they describe without that permission.

The `reason` values name real causes, for example `unknown`, `inactive` and `wrong_password` on LoginFailed. They are
deliberately not shown in HTTP answers (anti-enumeration), so they must stay restricted to administrators. The IP and
user agent are personal data: export or display must follow the data-protection policy.

## Log scrubbing (Serilog)

- **Properties.** `RedactionEnricher` (T09) masks sensitive property names and scrubs credential-shaped values:
  - Bearer and Basic values, and `key=value` pairs for password, token, secret, cookie and session;
  - JWTs;
  - since T17, also PHC password hashes, matched from the `$argon2id$` marker to whitespace, a quote or a semicolon.
    The match runs through the commas of the parameters (`m=65536,t=3,p=1`), so the salt and hash are hidden too.
  - Any opaque run of 43 or more base64url or hex characters, which covers our 43-character tokens.
  - Any run of 43 or more standard base64 characters (`+`, `/`, `=` padding) that mixes upper and lower case, and
    either has a digit or contains `+` or `/` (T18 audit L7). Our lower-case URL paths such as `/api/v1/auth/...`
    stay readable.
  - The enricher masks a property whose redaction throws, for example a value whose `ToString` fails (fail closed,
    tested).
  - GUIDs, trace ids and ordinary identifiers stay readable. Tested with a real Argon2 hash in a message, a property
    and an exception.
  - Pair keys match by role: exactly `code` or `code_verifier`, or a key ending in password, secret, token, apikey,
    cookie or otp. So `newPassword=` and `refresh_token=` are masked, while `StatusCode=` and `SessionId=` are not.
  - Every pattern has a 200 ms match timeout; a text that times out is masked whole.
  - Non-string scalars that are not plain values (a `Uri` with a token in its query, any type whose `ToString` carries
    text) are rendered, scrubbed, and replaced when something was masked.
- **Exceptions (T09 review, T17).** Serilog cannot change an event in place, so every sink is wrapped in
  `ExceptionScrubbingSink`. An event's exception reaches the sink as a `ScrubbedException` with:
  - the original type name;
  - the message and stack trace redacted the same way;
  - every inner exception scrubbed recursively, including all of an AggregateException's (depth and count bounded);
  - **no `Exception.Data`**;
  - the original type name also as an `ExceptionType` property, for structured sinks.
- **Which sinks.** The console sink and every sink registered in DI are wrapped in Program.cs; the test capture sink is
  one of those.
  - Sinks declared in configuration (`Serilog:WriteTo`) would bypass the wrapper, so they **stop the app at startup**.
    Add new sinks in Program.cs.
  - No file or database sink was added. Adding one needs a package, so it needs approval.
- **Tests.**
  - Unit: planted secrets in the message, inner exceptions, Data and stack trace never reach the sink.
  - Through the real host: a logged exception carrying secrets shows up scrubbed in the captured sink. A mutation that
    removes the wrapper fails this test.

## Retention purge

`IRetentionPurge` (Services) runs from the hosted service `RetentionPurgeService` every `Retention:Interval`. It is
**off by default** (`Retention:Enabled` = false): deleting data is an operator decision, and `appsettings.Example.json`
shows it enabled with the defaults below. **Operators must enable it in production.** Without it the audit table
grows without bound from unauthenticated events (failed logins, sign-ups, reset requests). Outside Development a
disabled purge logs a warning at every start (tested). A failed run is logged with the exception type only and retried
at the next interval.

| Data | Rule | Default |
|---|---|---|
| Pending registration (password hash, display name) on a verification link | erased as soon as the link expires unused; used links are erased when used | immediate |
| EmailVerificationToken, PasswordResetToken | deleted once used or expired for longer than `OneTimeTokens` (also covers links left by failed sends) | 7 days |
| Refresh tokens | only tokens of **ended families** (every token of the family expired or revoked for longer than `RefreshFamilies`), in row-bounded batches | 30 days |
| Audit rows, high-volume types | deleted after `HighVolumeAuditLog` | 90 days |
| Audit rows, all other types | deleted after `AuditLog` (at least 30 days) | 365 days |
| Audit rows of event types no longer in the enum (legacy, renamed) | deleted after `AuditLog` | 365 days |

- **Set-based and bounded by ROWS** (review MEDIUM-1: SQL Server escalates to a table lock at about 5000 row locks,
  which would block every login).
  - Each statement touches at most `BatchSize` rows (default 1000), or `RefreshTokenBatchSize` refresh token rows
    (default 500). Both are capped at 4000.
  - A long family (one row per rotation, up to about 2900 over 30 days) is removed over several statements. That is
    safe: an ended family stays ended, nothing can refresh it, and its first-token time only matters while it is live.
  - Each step first clears the rotation links (`ReplacedByTokenId`, a self foreign key) of up to a batch of rows of
    ended families, then deletes up to a batch of rows that nothing points to.
  - Each category runs at most `MaxBatchesPerRun` statements (50) per run, and the next run continues.
- **Idempotent and safe on several instances**, because every statement re-checks its own condition.
- **Live data is never touched.** Every statement filters on an end time before the cutoff:
  - a family with any token not yet ended before the cutoff is never touched;
  - so the 30-day absolute session cap (counted from a live family's first token) can never be extended.
- **Audit rows are purged per event type**, which uses the existing index `IX_AuditLog_EventType_OccurredUtc`. Rows
  with an event name that is not in the enum follow the normal retention (one scanning statement, batch-bounded).
- **Validation.** Retention settings that would purge too eagerly stop the app at startup: high-volume below 7 days,
  AuditLog below 30 days or below the high-volume value, one-time tokens or families below 1 day, a batch outside
  1 to 4000.
- **Tested** against SQL Express, with each test in its own past year so other rows of the shared database are never
  in range:
  - ended families only, including the self-referencing `ReplacedByTokenId`;
  - a family ended after the cutoff is kept, and so is a live family;
  - one 25-token family with a batch of 10: a run deletes at most 10 rows, later runs finish it, others untouched;
  - rows of an unknown event type are kept within retention and purged after it;
  - high-volume rows go before normal rows, and runs are bounded;
  - the pending payload is erased at expiry, and the row is deleted after retention.

**Follow-ups (not now):** an unlock-by-email link and a new-device sign-in email.

**Indexes (added in T18, human approved).** `IX_RefreshToken_ExpiresUtc`, `IX_EmailVerificationToken_ExpiresUtc` and
`IX_PasswordResetToken_ExpiresUtc` (migration `RetentionAndAudienceIndexes`). The purge queries are unchanged: their
expiry conditions can now seek instead of scanning. The ended-family check still uses `IX_RefreshToken_FamilyId`, and
`UsedUtc` has no index (used links are a small share of rows).

## Related

- Lockout failure window and level decay: rate-limiting-and-lockout.md.
- Session cap: sign-in-and-sessions.md.
