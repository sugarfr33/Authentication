# Backend test matrix (T25)

This page maps each security scenario the backend must cover to the tests that prove it.
- **Test suites:** `Auth.IntegrationTests` runs through the real pipeline against SQL Server; `Auth.UnitTests`; and
  `Auth.ArchitectureTests`.
- **Names:** tests are listed as `Class.Method`. Integration API tests live in `tests/Auth.IntegrationTests/Api`, and
  service tests live in `tests/Auth.IntegrationTests/Services`.
- **New in T25:** tests added by T25 are marked **(T25)**.
- **Mutation checks:** where a mutation check was run, the line names the production statement whose removal makes the
  test fail.

## 1. Refresh token rotation and reuse detection

| Scenario | Tests |
|---|---|
| Browser refresh over HTTP rotates the cookie (same family, old row `Rotated`) | `SecurityScenarioApiTests.Refresh_rotates_the_cookie_and_a_replayed_old_token_revokes_the_whole_family_and_is_audited` **(T25)** |
| Replaying a rotated token after the grace window revokes the whole family, including the victim's current cookie and access session, and audits `TokenReuse` | same test **(T25)**. Mutation: removing `RevokeFamilyAsync(..., Reuse)` in `RefreshTokenService` fails it. Service level: `RefreshTokenServiceTests.Replaying_a_rotated_token_after_the_grace_window_revokes_the_whole_family` |
| A double submit inside the grace window from the same browser is not reuse | `SecurityScenarioApiTests.Within_the_grace_window_a_double_submitted_refresh_from_the_same_browser_is_not_reuse` **(T25)**; `RefreshTokenServiceTests.Within_the_grace_window_a_different_user_agent_is_treated_as_reuse` |
| A token revoked by logout and then replayed is reuse | `RefreshTokenServiceTests.A_token_revoked_by_logout_and_replayed_is_reuse`; `RefreshServiceTests.Replaying_an_ended_session_is_rejected_but_only_real_reuse_is_audited_as_reuse` |
| A stolen browser token replayed also ends the application sessions | `SingleLogoutApiTests.A_stolen_browser_refresh_token_replayed_ends_the_application_sessions` |
| Application (OAuth) refresh rotation and reuse | `OAuthApiTests.The_full_flow_issues_app_tokens_that_refresh_and_detect_reuse_and_never_unlock_this_API`; `OAuthExchangeTests.A_replay_revokes_the_family_recorded_on_the_code_and_starts_nothing` |
| Concurrent rotation of one token | `RefreshTokenRepositoryTests.Concurrent_rotation_of_the_same_token_raises_ConcurrencyConflictException` |
| Sliding and absolute lifetime | `RefreshTokenServiceTests.Lifetime_slides_14_days_per_rotation_but_never_past_30_days_from_the_family_start` |
| The refresh cookie never signs anyone in, and is scoped to the auth routes | `SessionApiTests.The_refresh_cookie_reaches_the_auth_routes_only_and_never_signs_anyone_in` |

## 2. Lockout and its decay

| Scenario | Tests |
|---|---|
| Five wrong passwords lock the account. While it is locked, the right password gets the same answer. | `SessionApiTests.Five_wrong_passwords_lock_the_account_and_the_right_one_then_fails_the_same_way`; `LockoutServiceTests.Fifth_failure_locks_for_one_minute_and_reports_the_event` |
| Old failures decay by one per quiet window, so paced guessing never locks (over HTTP) | `SecurityScenarioApiTests.Old_failures_decay_one_per_quiet_hour_so_paced_guessing_never_reaches_the_lock` **(T25)**; `LockoutServiceTests.Failures_decay_by_one_per_quiet_window`, `Pacing_after_a_burst_allows_about_one_guess_per_window` |
| Each lock doubles, and a quiet day forgets the backoff (over HTTP) | `SecurityScenarioApiTests.Each_lock_doubles_until_a_quiet_day_forgets_the_backoff` **(T25)**; `LockoutServiceTests.Backoff_doubles_with_each_lock_and_is_capped_at_one_hour`, `The_backoff_level_decays_after_a_quiet_period`. Mutation: removing either decay fails the T25 tests. |
| Failures while locked are not counted; success resets everything | `LockoutServiceTests.Failures_while_locked_are_not_counted_and_the_lock_expires`, `Success_resets_the_counter_the_lock_and_the_backoff_level` |
| No lost updates under concurrency | `LockoutServiceTests.Concurrent_failures_are_never_lost` |
| Wrong MFA codes and wrong current passwords count too | `MfaApiTests.Wrong_codes_count_toward_the_lockout_like_wrong_passwords`; `PasswordServiceTests.Change_password_needs_the_current_one_and_counts_wrong_attempts_toward_lockout` |
| No timing or answer difference between unknown, inactive, locked and wrong password | `SessionApiTests.Every_failed_login_reason_gets_the_identical_answer_and_no_cookies`; `HashingGuardTests.Unknown_inactive_locked_and_wrong_password_paths_each_cost_exactly_one_Verify_and_look_the_same` |
| Admin reactivation clears the lockout | `AdminApiTests.Reactivation_clears_the_lockout` |
| Pipeline order: the per-IP limiter runs before `AccountKeyMiddleware`, so an oversized body still costs an IP permit (mutation-checked by swapping the two in Program.cs) | `RateLimitTests.The_IP_limit_counts_before_the_body_is_read` **(T29)** |

## 3. CSRF and origin

| Scenario | Tests |
|---|---|
| A GET issues the readable XSRF cookie and the HttpOnly antiforgery cookie | `CookieAuthTests.GET_issues_a_readable_XSRF_cookie_and_an_HttpOnly_antiforgery_cookie` |
| State changes need a matching XSRF header | `CookieAuthTests.State_changing_requests_need_a_matching_XSRF_header`; `SessionApiTests.State_changing_calls_need_the_antiforgery_token`; `RegistrationApiTests.Register_without_the_antiforgery_token_is_refused`; `PasswordApiTests.Change_password_needs_the_antiforgery_token_and_the_current_password`; `SessionsListApiTests.Revoking_needs_the_antiforgery_token_and_listing_needs_a_session`; `AdminApiTests.State_changes_need_the_antiforgery_token_and_a_JSON_body` |
| Tokens are bound to the user and re-issued after sign-in | `CookieAuthTests.Antiforgery_tokens_are_bound_to_the_user_and_are_reissued_after_sign_in`; `SessionsListApiTests.After_the_access_cookie_expires_the_SPA_must_GET_first_then_refresh` |
| A missing Origin and Referer gets 403; Referer is the fallback; only same-origin and trusted origins are accepted | `CookieAuthTests.Missing_Origin_and_Referer_is_403_unless_explicitly_allowed`, `Referer_is_the_fallback_and_same_origin_and_trusted_origins_are_allowed`; `AdminApiTests.State_changes_need_the_antiforgery_token_and_a_JSON_body` (foreign origin 403) |
| Production refuses unsafe origin settings | `BrowserProtectionHardeningTests.*` (5 tests) |
| OAuth and logout endpoints accept only the client's own origin | `OAuthApiTests.The_token_endpoint_requires_the_clients_own_origin_and_a_form_body`; `SingleLogoutApiTests.The_logout_confirmation_only_comes_from_the_applications_own_origin_or_the_auth_UI`; `OAuthRateLimitMapTests.Only_the_token_endpoint_opts_out_of_antiforgery`; `MfaRouteMapTests.Every_MFA_route_is_rate_limited_declares_its_access_and_keeps_antiforgery` |

## 4. Forged and invalid JWTs (cookie access token)

| Scenario | Tests |
|---|---|
| A correctly signed token with a live session is accepted (the control) | `CookieAuthTests.A_correctly_signed_token_in_the_cookie_is_accepted` |
| alg=none, HS256 with the public key (algorithm confusion), expired, wrong audience, wrong issuer, wrong key, garbage, oversized | `CookieAuthTests.Forged_expired_and_misdirected_tokens_get_401` |
| Tampered payload (role escalation, other subject), tampered or stripped signature, hand-made `alg:none` header (with and without a signature), not yet valid (nbf in the future) | `CookieAuthTests.A_tampered_payload_a_not_yet_valid_token_and_a_hand_made_alg_none_header_get_401` **(T25)** |
| A valid signature without a live session | `CookieAuthTests.A_correctly_signed_token_without_a_live_session_gets_401`; `LiveSessionApiTests.*` (4 tests) |
| Bearer header ignored (cookie only); application tokens never unlock this API | `CookieAuthTests.A_valid_token_in_the_Authorization_header_is_ignored_cookie_only`; `ClientApplicationApiTests.A_token_with_a_client_id_is_never_a_browser_session_of_this_API`, `An_app_token_carries_the_app_audience_client_id_session_and_app_roles_but_never_unlocks_this_API` |
| Claims from anyone but the server are never trusted | `AuthorizationApiTests.Claims_signed_by_anyone_but_the_server_are_never_trusted` |
| Signing key rotation and JWKS | `SigningKeyRotationTests.*` (unit); `CentralAuthClientTests.A_token_signed_with_a_rotated_key_is_accepted_after_one_rate_limited_refresh` |
| `signing-key add` command: usage checked before the host, overlap refusal, one-line failures with no stack trace or message leak, PEM refused as `--reference`; each added key audited (kid, algorithm, activation only) **(T29)** | `SigningKeyCommandTests.*`; `SigningKeyRotationTests.An_added_key_stages_one_SigningKeyAdded_row_with_kid_algorithm_and_activation_only`, `A_refused_key_stages_no_audit_row`; `AuditDetailTests.A_signing_key_kid_is_written_only_when_it_is_plain`; `AdminApiTests.Adding_a_signing_key_writes_a_SigningKeyAdded_row_with_kid_and_algorithm_only` |

## 5. CORS

| Scenario | Tests |
|---|---|
| A preflight from an allowed origin lists exactly that origin, with credentials | `CookieAuthTests.Preflight_from_an_allowed_origin_lists_exactly_that_origin_with_credentials` |
| Unknown or inactive origins get no CORS headers | `CookieAuthTests.Unknown_or_inactive_origins_get_no_CORS_headers` |
| Exactly the registered active origins; a lookalike is refused; deactivation applies at once | `ClientApplicationApiTests.CORS_allows_exactly_the_registered_active_origins_and_drops_a_deactivated_app_at_once` |
| Admin API: create, deactivate, activate, and an update that moves the origin | `AdminApiTests.Client_applications_are_managed_through_the_registry_with_audit_and_CORS_invalidation` |
| Changing origins keeps sessions; changing the audience ends them | `ClientApplicationRegistryTests.Changing_the_audience_ends_the_applications_sessions_but_changing_origins_does_not` |

## 6. MFA

| Scenario | Tests (all in `MfaApiTests`) |
|---|---|
| Flag off: routes return 404, and accounts with MFA fail closed | `With_the_flag_off_MFA_routes_are_404_and_accounts_with_MFA_fail_closed_like_a_wrong_password` |
| Enrollment, recovery codes shown once, all sessions ended | `Enrollment_is_confirmed_by_a_code_shows_recovery_codes_once_and_ends_every_session` |
| Login challenge, code, single use | `Login_with_MFA_needs_the_challenge_and_a_code_and_the_challenge_works_once` |
| Wrong codes count toward lockout | `Wrong_codes_count_toward_the_lockout_like_wrong_passwords` |
| Recovery codes are single use under concurrency; regeneration | `A_recovery_code_works_once_even_when_used_concurrently_and_regeneration_replaces_them` |
| Disable (password and code), admin reset | `Disabling_needs_the_password_and_a_code_and_ends_every_session`; `An_admin_reset_turns_MFA_off_and_ends_every_session`; `AdminApiTests.Admin_MFA_reset_ends_every_session_and_is_audited_as_reset_with_the_actor` |
| Races, expiry, secrets never logged, missing keys stop the host | `A_verify_that_loses_a_race_is_retried_and_a_lost_recovery_code_spend_is_rolled_back`; `A_double_submitted_code_starts_one_session_and_the_loser_is_not_a_strike`; `A_confirm_that_loses_a_race_answers_409_never_500_and_is_not_a_strike`; `A_pending_enrollment_expires_after_15_minutes`; `Secrets_codes_and_challenges_never_reach_logs_or_audit_rows`; `With_the_flag_on_missing_keys_stop_the_host` |

## 7. Admin policies end to end (all in `AdminApiTests`)

| Scenario | Tests |
|---|---|
| Every endpoint returns 403 without its permission, for each permission holder; 401 without a session | `Every_admin_endpoint_answers_403_without_its_permission` (one theory case per holder); `Without_a_session_every_admin_endpoint_answers_401` |
| A principal without a usable `sub` gets no actor (403) | `AdminActorTests.*` (unit) |
| Privilege ceiling | `A_role_manager_who_is_not_an_administrator_can_only_give_rights_they_hold`; `A_user_writer_who_is_not_an_administrator_cannot_change_an_administrators_account` |
| Last administrator, stale administrator, concurrent demotion and deactivation, self-lockout | `The_last_active_administrator_cannot_be_demoted_or_deactivated`; `Removing_the_Admin_role_from_a_stale_account_is_not_refused_as_the_last_administrator`; `Two_administrators_demoting_each_other_at_once_leave_one_administrator`; `Two_administrators_deactivating_each_other_at_once_leave_one_active_administrator`; `Administrators_cannot_lock_themselves_out_or_strip_the_Admin_role` |
| An audit row with the actor for each change | `Assigning_and_removing_a_role_…`; `Granting_and_removing_a_permission_…`; `Deactivating_a_user_…`; `Admin_MFA_reset_…`; `Client_applications_…`; `AuditCoverageTests` maps every `AuditEventType` to its persisted-row test |
| Audit reasons visible only to `audit.read`; no secrets; caps; CSRF, JSON, 413 and rate limit | `Audit_rows_and_their_reasons_are_shown_only_to_audit_readers`; `Reads_return_no_secrets_and_lists_are_capped`; `State_changes_need_the_antiforgery_token_and_a_JSON_body`; `The_admin_API_has_its_own_rate_limit` |
| Default-deny route pin (every non-anonymous route requires authorization) | `AuthorizationApiTests.Every_endpoint_requires_authorization_unless_it_is_explicitly_anonymous` |

## Running the database suites reliably

The integration suites create one throwaway database per fixture and run. The name is unique (`CentralAuth_…_run<id>_Test`),
and the `_Test` guard refuses any other name. The tests share one local SQL Express (or LocalDB) instance with every
other run on the machine.

**Warm-up (T25).** Each fixture uses `TestDatabaseWarmup` (`tests/Auth.IntegrationTests/DAL`) around its schema step:

1. `WaitForServerAsync` before the schema step;
2. `RetryAsync` for the delete-and-migrate schema step itself;
3. `WarmPoolAsync` after it.

Together they do two things:

- **Retries transient failures.** It retries the first connection until SQL Server answers: login timeouts, prelogin
  delays, error 17189 "failed to spawn a thread", and the server-side transport errors seen when the instance is cold or
  the box is short of memory.
- **Warms the pool.** It then opens a burst of parallel connections. That fills this process's connection pool and makes
  SQL Server create the worker threads that concurrency tests need at once (for example 16 racing password resets),
  instead of the first real request paying for it with a 30 s timeout or a 500.

**If the suites still time out:**

1. Look for `Error: 17189` in the SQL Server error log
   (`EXEC xp_readerrorlog 0, 1, N'17189'`). If it is there, the machine lacks memory or threads. Close other heavy test
   runs, or run the DB suites one at a time.
2. If `sqlcmd -S .\SQLEXPRESS -E -Q "SELECT 1"` itself times out with no test running, the instance is wedged. Restart
   the `MSSQL$SQLEXPRESS` service. It holds only throwaway `_Test` databases.
3. Set `CENTRALAUTH_TEST_CONNECTION` to use another server. The database name still gets the unique `_Test` suffix.
