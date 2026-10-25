# MFA admin recovery runbook (T21 FIX, F1)

**Who this is for:** the operator of the CentralAuth database.

**When to use it:** a user with MFA on can no longer sign in, because either:

- they lost both their authenticator device and every recovery code; or
- `Mfa:Enabled` was turned off while they still have MFA on (they fail closed, see docs/mfa-totp.md section 1).

There is no admin endpoint yet; one is a separate task. Until it exists, this runbook is the only supported way to turn
MFA off for someone else. **MFA must not be enabled for real users until the admin endpoint exists or the operator has
accepted this runbook** (docs/mfa-totp.md, "Production gate").

When the host can run code, prefer `IMfaService.ResetAsync(userId, ...)`: it does the same steps, audits
`MfaDisabled {"action":"reset"}` and publishes the single-logout event to end the application sessions at once. The
SQL below is for when only database access is available.

## 1. Verify the person first

Turning MFA off removes the second factor, so an attacker who has the password would want exactly this. Before running
anything:

- Do not act on a request that came only by email or chat from the account's address: that address may be compromised.
- Confirm the identity through a channel set up beforehand: a call-back to a known phone number, the person's manager,
  in-person ID, or the organisation's helpdesk identity procedure.
- Write down who asked, who verified, how, and when. This goes into the audit note (step 3).
- Prefer telling the user to **change their password** right after signing in again.

## 2. Reset (one transaction)

Replace the email. Run on the CentralAuth database, never on a `_Test` copy by mistake, and check that the first
`SELECT` returns exactly one row.

```sql
DECLARE @Email nvarchar(256) = N'user@example.com';
DECLARE @Now datetime2(7) = SYSUTCDATETIME();
DECLARE @UserId uniqueidentifier;

SELECT @UserId = [Id] FROM [auth].[User] WHERE [NormalizedEmail] = UPPER(TRIM(@Email));
SELECT [Id], [Email], [MfaEnabled], [IsActive] FROM [auth].[User] WHERE [Id] = @UserId;  -- exactly one row

BEGIN TRANSACTION;

-- MFA off, the secret gone, every outstanding challenge and access-token check invalidated (new stamp).
UPDATE [auth].[User]
SET [MfaEnabled] = 0,
    [MfaSecretEncrypted] = NULL,
    [SecurityStamp] = NEWID(),
    [UpdatedUtc] = @Now
WHERE [Id] = @UserId;

-- Recovery codes gone (the service marks them used; deleting is equivalent here).
DELETE FROM [auth].[MfaRecoveryCode] WHERE [UserId] = @UserId;

-- Every session (browser and application) revoked. RevokedReason is CHECK-constrained: 'Admin' is the right value.
UPDATE [auth].[RefreshToken]
SET [RevokedUtc] = @Now,
    [RevokedReason] = N'Admin'
WHERE [UserId] = @UserId AND [RevokedUtc] IS NULL;

-- Unredeemed authorization codes cannot start a new application session afterwards.
DELETE FROM [auth].[AuthorizationCode] WHERE [UserId] = @UserId AND [UsedUtc] IS NULL;

COMMIT TRANSACTION;
```


## 3. Audit note

The service would write this row itself; by hand, add it in the same session. `Detail` holds only catalogue words (no
names, no ticket text): keep the verification record (step 1) in the ticket system, not in the audit row.

```sql
INSERT INTO [auth].[AuditLog] ([OccurredUtc], [EventType], [UserId], [Detail])
VALUES (SYSUTCDATETIME(), N'MfaDisabled', @UserId, N'{"action":"reset"}');
```

## 4. What happens next

- **Browser sessions** stop within `SessionLiveness:CacheDuration` (at most 30 s): their refresh families are revoked.
- **Application sessions** cannot refresh any more. An application access token already issued stays valid until it
  expires (minutes), because the single-logout event is published only by the service, not by SQL.
- The user signs in with their password alone. They can enroll MFA again from their account (new secret, new codes).
- Expect one `LoginSucceeded` for the user afterwards. A `MfaFailed` or `LoginFailed` burst right after the reset is a
  sign that someone else is trying the account.

## 5. Flag turned off for everyone

If `Mfa:Enabled` was turned off on purpose and MFA users must sign in again, do **not** run this for every user
blindly: turning the flag back on is the safe fix, and their factors still work. Reset only the users who ask, after
verifying them.
