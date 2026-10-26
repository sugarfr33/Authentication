# Optional TOTP MFA (T21)

Status: **implemented.** No schema change was needed: the existing schema already has everything (section 2).

Implementation map:

| Part | Where |
|---|---|
| Endpoints | `MfaEndpoints` (Auth.Api), mapped only when `Mfa:Enabled` is true |
| Service | `IMfaService` (Auth.Services/Mfa): enroll, confirm, regenerate, disable, reset, verify |
| TOTP and base32 | `Totp`, `Base32` (hand-written) |
| Keys, blob, pepper | `IMfaCrypto`; checked at startup by `MfaKeyCheckOnStartup` |
| Challenge | `IMfaChallenges` |
| Shared session start | `IBrowserSessionStarter`, used by password login and by MFA verify |

Tests:

- integration: `MfaApiTests`;
- unit: `TotpAndMfaCryptoTests` and `MfaRouteMapTests`.

What changed from the design during the build is marked **Built:**; the review fixes are marked **Fix:**.

## Production gate

The admin MFA reset endpoint now exists (T21b): `POST /api/v1/admin/users/{id}/mfa/reset`, with its runbook in
docs/admin-api.md. Before enabling MFA for real users, make sure an operator holds `users.write` and knows the
identity checks. The SQL runbook (docs/mfa-admin-recovery.md) is the fallback when the API is unavailable.

## 1. Feature flag

`Mfa:Enabled`, default **false**.

- **Off:** no `/api/v1/auth/mfa/*` route is mapped, so every MFA endpoint answers 404 (tested). Login for users
  without MFA is unchanged.
- **Off while some users have `MfaEnabled = true`: fail closed.** Such users cannot sign in with the password alone.
  - Login answers the same generic 401 as a wrong password, after the same work (timing guard, one lockout round
    trip, one audit row with reason `mfa_unavailable`).
  - Protection is never silently lost.
  - To let them in, an operator re-enables the flag or resets their MFA (`IMfaService.ResetAsync`, service only, no
    endpoint); a reset ends their sessions.
  - Documented as an operational rule: turning the flag off is **not** a way to disable MFA for everyone.
- **On:** the second-factor challenge replaces the current `mfa_not_supported` refusal (section 5).

## 2. Storage (existing schema, no change)

| Need | Where |
|---|---|
| TOTP secret, encrypted | `User.MfaSecretEncrypted` varbinary(256), null when MFA is off |
| MFA on or off | `User.MfaEnabled` (true only after the enrollment is confirmed) |
| Replay protection (last time step used) | **inside** the encrypted blob (below) |
| Recovery codes | `auth.MfaRecoveryCode` (`CodeHash` binary(32), `UsedUtc`), through the existing `IOneTimeTokenRepository<MfaRecoveryCode>` |

### The secret blob

The blob is versioned and protected with **AES-256-GCM**, using `System.Security.Cryptography.AesGcm` (no package):

```
[0] format version (1)
[1] key id length n, [2..2+n) key id (ASCII, at most 16)
[..+12] nonce (random)
[..+28] ciphertext of (20-byte secret || 8-byte last used time step, big-endian)
[..+16] tag
```

- **Associated data:** the user id, so a blob copied to another user row fails to decrypt.
- **Size:** about 75 bytes, well under 256.
- **Keys** (**Fix:** names aligned with the code):
  - each key is the `ISecretStore` secret `MfaEncryptionKey-<id>`, base64 of 32 random bytes (configuration
    `Secrets:MfaEncryptionKey-<id>`, environment variable `Secrets__MfaEncryptionKey-<id>`). Secret names cannot
    contain a colon, hence the hyphen;
  - `Mfa:KeyIds` lists the ids that can decrypt; `Mfa:ActiveKeyId` (one of them) selects the key for new writes;
  - the recovery pepper is the secret `MfaRecoveryPepper` (`Secrets__MfaRecoveryPepper`), also 32 bytes;
  - missing or short keys, an active id that is not listed, or a pepper equal to an encryption key stop the app at
    startup when the flag is on.
- **Rotation:** add the new key and its id to `Mfa:KeyIds`, switch `Mfa:ActiveKeyId`, and **keep the old id listed
  until every blob has been rewritten.** Every successful verify rewrites the blob with the active key; a blob of a
  user who never signs in again stays on the old key (re-enrolling or an admin reset clears it).
  - A blob whose key id is no longer listed cannot be read: the user's codes look wrong and count toward the lockout
    (recovery codes still work). **Fix:** each unreadable blob logs a warning with the problem (`unknown_key` or
    `tag_mismatch`) and the key id only, at most once a minute per key id.
- **Writes:** every successful TOTP verify rewrites the blob (new nonce, new last step) with the user row's
  `RowVersion` concurrency check.
  - Of two concurrent verifies with the same code, only one wins.
  - A code, or any earlier step, can never be used again (replay protection without a column).
- **Logs:** the plain secret exists only in memory, while a code is checked and in the one enroll answer. It is
  never logged or audited.

## 3. TOTP (RFC 6238, hand-written)

- HMAC-SHA1 over the 8-byte big-endian time step: a 30 s step from the Unix epoch (`IClock`), 6 digits, dynamic
  truncation as in RFC 4226.
- The secret is 20 random bytes (160 bits), shown as base32 without padding.
- **Window ±1 step.** A code is accepted for step `s` only when `s > lastUsedStep`.
- Comparison with `CryptographicOperations.FixedTimeEquals` over the digit bytes. Candidate steps are checked in a
  fixed order with no early exit.
- Input: exactly 6 ASCII digits after trimming spaces; anything else is a wrong code (counted).
- Tests: the RFC 6238 appendix B SHA-1 vectors (8 digits at T = 59, 1111111109, 1111111111, 1234567890, 2000000000,
  20000000000), the 6-digit truncation, the window edges and replay.

## 4. Enrollment, recovery codes, disable

All of these need the signed-in browser session, JSON, the Origin check and the antiforgery token (default-deny
metadata, `RequireAuthorization`). None of them works with a Bearer application token.

- **`POST /auth/mfa/enroll {password}`**:
  - **re-authentication**: the current password, checked through the timing guard. A wrong password counts toward
    the lockout, audits `MfaFailed` with reason `wrong_password`, and answers 400 (the user is signed in, so not
    401);
  - creates a new secret, stored encrypted with `MfaEnabled` left **false** (pending), and replaces any earlier
    pending secret; audits `MfaEnrollmentStarted` (**Fix:** its own event, since MFA is not on yet);
  - **Fix: the pending secret expires after 15 minutes** (`MfaService.PendingEnrollmentLifetime`), counted from the
    account row's `UpdatedUtc` (no new column). Confirm then answers 409 and the user enrolls again. A wrong confirm
    code also updates `UpdatedUtc` (lockout counter), which extends the window; it is still bounded by the lockout.
    An expired pending secret stays encrypted in the row until the next enroll, confirm or reset (it can no longer be
    confirmed); the retention purge does not clear it;
  - answers once with the `otpauth://totp/CentralAuth:<email>?secret=...&issuer=CentralAuth&digits=6&period=30` URI
    and the base32 manual-entry key, with `no-store`. Neither is ever logged;
  - if MFA is already on: 409.
- **`POST /auth/mfa/confirm {code}`**:
  - a valid code for the pending secret flips `MfaEnabled` to true and stores the step;
  - generates **10 recovery codes** and answers them once (`no-store`);
  - audits `MfaEnabled`;
  - **ends every session of the user** (`SessionEnded` scope All, cause `MfaEnrolled`) and clears this browser's
    cookies, so the next sign-in uses the second factor; sessions opened with the password alone do not survive;
  - a wrong code counts toward the lockout;
  - **Fix:** two concurrent confirms (double submit), or a confirm that loses a race with any other change of the
    account row, answer **409** with no strike and nothing changed (the factor check, the recovery codes, the session
    revocation and the audit row are one transaction). Never a 500. The same holds for regenerate and disable.
- **`POST /auth/mfa/recovery-codes {password, code}`** (regenerate): with the password and a valid TOTP code, all
  old codes are invalidated in one UPDATE and 10 new ones are shown once.
- **`POST /auth/mfa/disable {password, code}`**: with the password and a valid TOTP code (or a recovery code), it:
  - clears the secret and `MfaEnabled`;
  - invalidates the recovery codes;
  - changes the `SecurityStamp`;
  - **ends every session** (cause `MfaDisabled`, scope All, published after the revocation);
  - a recovery code is spent in the same transaction as the change, so a lost race does not burn it;
  - audits; the cookies are cleared.
- **Admin reset** (`IMfaService.ResetAsync`, service only, no endpoint): does the same as disable without the
  factors (cause `MfaReset`). By hand: docs/mfa-admin-recovery.md.
- **Revocation reason (Fix, L4):** the refresh rows revoked by enroll, disable and reset keep `RevokedReason`
  `PasswordChange` (a credential change), because the column is CHECK-constrained and the schema does not change. The
  real cause is in the audit row (`MfaEnabled`, `MfaDisabled`) and in the `SessionEnded` cause.

### Recovery codes

- Each code is 10 characters from the 32-letter unambiguous alphabet `23456789ABCDEFGHJKLMNPQRSTUVWXYZ` (50 bits).
  Shown as `XXXXX-XXXXX`; input ignores case, spaces and the hyphen.
- **Stored as HMAC-SHA256 with a server pepper** (the secret `MfaRecoveryPepper`, 32 bytes, not rotated): this fits
  `CodeHash` binary(32) and allows lookup by hash.
  - A plain SHA-256 of 50 bits could be brute-forced offline after a database leak (about a day per code on one GPU).
    With the pepper, the database alone is not enough.
  - Argon2 would need one costly verify per stored code on each attempt.
  - **Pepper rotation is not supported:** a new pepper makes every stored code unusable. After any pepper change,
    every MFA user must regenerate their recovery codes.
- **Single use:** the conditional UPDATE `UsedUtc = now WHERE Id = @id AND UsedUtc IS NULL`, as for the other
  one-time tokens. Of two concurrent uses, one wins (tested).
- **Built: lookup by hash, no index.** `MfaRecoveryCode.CodeHash` has no index (adding one is a schema change). The
  table holds 10 rows per MFA user, so the lookup is a small scan. Add the index if MFA adoption grows large.

## 5. Login with the second factor

1. `POST /auth/login` runs exactly as today until the password check. **Nothing distinguishes MFA users before the
   password is proven:**
   - unknown email, wrong password, locked and disabled accounts all answer the same 401 after the same work;
   - the timing guard does one Verify either way.
2. **Password correct and `MfaEnabled` (flag on):**
   - no session is started, and **the lockout counter is NOT reset** (otherwise an attacker who knows the password
     could alternate password and code guesses forever);
   - the API sets a **challenge cookie** `__Secure-mfa`: HttpOnly, Secure, SameSite Strict, host-only (no Domain, in
     both cookie modes), Path `/api/v1/auth/mfa`, Max-Age 300;
   - **Built:** the name is `__Secure-mfa`, not `__Host-mfa`, because the `__Host-` prefix requires `Path=/`, and the
     narrow path matters more;
   - the answer is `202 {"mfa_required": true}`. Tokens never travel in a body, and the challenge is a credential, so
     it is a cookie.
3. **The challenge** is stateless (no table) and signed with HMAC-SHA256. Its MAC key is derived with `HKDF` from the
   active MFA encryption key (info `mfa-challenge-v1`). Payload:
   - the user id and the expiry (5 minutes);
   - SHA-256 of the user's `SecurityStamp`;
   - SHA-256 of the current secret blob. A successful MFA sign-in always rewrites the blob (TOTP: new step; recovery
     code: new nonce), so a challenge is **single use** without storage;
   - SHA-256 of the User-Agent. Not the IP: mobile networks change it.

   It is checked in constant time. Expired, altered, used or mismatched challenges all get the same 401.

   - **Fix (L1):** a bad challenge is audited `MfaFailed bad_challenge` **without a user id**: the id inside an
     unverified challenge is attacker-chosen, so it must not attribute rows to a victim.
   - **Cookie tossing (L2, accepted):** the cookie is `__Secure-mfa`, not `__Host-`. In shared-domain mode a sibling
     subdomain could plant its own challenge cookie for this path. That only makes the victim's verify fail (the
     planted challenge names the attacker's account and needs the attacker's code); it cannot sign anyone in. It is a
     denial of service at most, and the victim signs in again. A per-login nonce in a second `__Host-` cookie would
     close it; it is not built (not cheap enough for the gain).
   - The User-Agent binding is weak (attacker-chosen); it only stops a copied cookie being used from another browser
     without changing its User-Agent. The factor and the lockout are the real protection.
4. **`POST /auth/mfa/verify {code, isRecoveryCode}`** (anonymous; the challenge cookie is the credential; Origin and
   antiforgery apply):
   - a locked account, a wrong TOTP code, a wrong or used recovery code: lockout `RegisterFailureAsync` (the shared
     service, as for a wrong password), audit `MfaFailed` with a reason only, and the same 401;
   - correct: the **shared internal browser-session starter** (extracted from `LoginAsync`) resets the lockout,
     applies the session cap, issues the family, rehashes if needed and audits `LoginSucceeded`, plus `MfaVerified`
     or `MfaRecoveryCodeUsed`;
   - the auth cookies are written and the challenge cookie is expired;
   - **Built:** a wrong code keeps the challenge, so the user can type the next code; the lockout bounds the
     guesses.
   - **No per-challenge attempt cap (L7, documented):** a cap needs state or would duplicate the account lockout.
     Whoever holds a challenge already knows the password and can get a new challenge at any time, so a per-challenge
     cap adds nothing. The bounds are the account lockout (5 failures, then doubling lockouts) and the per-IP
     `MfaVerify` limit.
   - **Fix (M1): races are not strikes.** The factor check and its write (the new last step, or the recovery code
     spend plus a fresh nonce) are one transaction under the user row's `RowVersion`. When that save loses a race (a
     concurrent lockout write, a double submit), or the code looks replayed, the service reloads the user and checks
     once more against fresh state:
     - if a concurrent sign-in used this challenge, it is now stale: `bad_challenge`, no strike;
     - if the code is still valid, the sign-in succeeds;
     - if it is still a replay, it is a genuine one and counts;
     - a second lost race answers 401 with audit reason `conflict` and no strike.

     A recovery code spent by a losing attempt is rolled back, so it still works. A double-submitted code starts one
     session and the other request is refused without a strike (tested).
   - **Built:** the password hash of an MFA account is not upgraded at sign-in, because the password is not
     available at the verify step. It is upgraded when the password changes, or at a sign-in after MFA is turned off.
5. **Rate limits:**
   - new kind `MfaVerify`, 10 per minute per IP (the lockout bounds guesses per account anyway);
   - new kind `MfaManage` for enroll, confirm, disable and regenerate, 10 per 15 minutes per IP;
   - both go in the path map (the architecture test covers the OAuth routes; an equivalent test covers the MFA routes).

## 6. Audit, logs, events

- **Audit events** (the reserved catalogue names, now used; details are words and ids only):
  - `MfaEnrollmentStarted` (**Fix:** its own event);
  - `MfaEnabled` with an `action` word: `enrolled` or `regenerated`;
  - `MfaDisabled` (**Fix:** its own event) with an `action` word: `disabled` (by the user) or `reset` (by an
    administrator);
  - `MfaVerified`;
  - `MfaFailed` with a reason: `wrong_code`, `wrong_recovery_code`, `replayed`, `locked`, `bad_challenge` (no user
    id), `wrong_password`, `conflict` (no strike);
  - `MfaRecoveryCodeUsed` (**Built:** without a count; counting the remaining codes would need one more query per
    sign-in).
- **Never in logs or audit:** codes, recovery codes, secrets, the otpauth URI or the challenge. The log redaction
  already masks keys ending in `otp` and `secret`, and `code`; a test plants them.
- **`SessionEndCause`** values `MfaEnrolled`, `MfaDisabled` and `MfaReset`, scope All, published after the
  revocation. The architecture rule (revoking types publish) covers the new service.
- **No `ISessionStarted`** event (as advised by the architect). The internal starter is the only seam.

## 7. Decisions taken

These were the defaults proposed in the design note; none needed a schema change:

1. flag off fails closed for users who have MFA;
2. confirming enrollment ends every session;
3. recovery codes use an HMAC pepper;
4. the challenge is a stateless signed cookie, single use through the blob fingerprint and bound to the User-Agent.
