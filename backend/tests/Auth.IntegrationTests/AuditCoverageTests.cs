using System.Reflection;
using Auth.Contracts;
using Auth.Services.Audit;

namespace Auth.IntegrationTests;

/// <summary>
/// T17 acceptance: walks every AuditEventType. A written type must name a test that asserts its persisted row (the
/// method must exist and be a test); a reserved type must not be written yet (no factory, checked in the unit tests).
/// Adding an event type without a test, or deleting the test, fails here.
/// </summary>
public class AuditCoverageTests
{
    private const string Trail = "Api.AuditTrailApiTests.Every_account_event_is_persisted_and_no_row_or_log_line_holds_a_secret";

    private static readonly Dictionary<AuditEventType, string> CoveredBy = new()
    {
        [AuditEventType.Registered] = Trail,
        [AuditEventType.EmailVerified] = Trail,
        [AuditEventType.LoginSucceeded] = Trail,
        [AuditEventType.LoginFailed] = Trail,
        [AuditEventType.Lockout] = "Api.SessionApiTests.Five_wrong_passwords_lock_the_account_and_the_right_one_then_fails_the_same_way",
        [AuditEventType.Logout] = "Api.SessionApiTests.Logout_clears_both_cookies_revokes_the_family_and_reissues_XSRF",
        [AuditEventType.LogoutAll] = "Api.SessionApiTests.Logout_all_revokes_every_session_of_the_user",
        [AuditEventType.TokenRefreshed] = Trail,
        [AuditEventType.TokenReuse] = "Services.RefreshServiceTests.Replaying_an_ended_session_is_rejected_but_only_real_reuse_is_audited_as_reuse",
        [AuditEventType.SessionRevoked] = "Api.SessionsListApiTests.A_revoked_session_cannot_refresh_and_revoking_again_is_harmless",
        [AuditEventType.PasswordResetRequested] = Trail,
        [AuditEventType.PasswordReset] = Trail,
        [AuditEventType.PasswordChanged] = Trail,
        [AuditEventType.EmailVerificationFailed] = Trail,
        [AuditEventType.RegistrationRejected] = Trail,
        [AuditEventType.PasswordResetFailed] = Trail,
        [AuditEventType.PasswordChangeFailed] = Trail,
        [AuditEventType.RefreshRejected] = "Services.RefreshServiceTests.A_credential_change_during_rotation_revokes_the_new_session",
        [AuditEventType.RoleAssigned] = "Services.AuthorizationSeederTests.The_bootstrap_admin_is_assigned_only_when_verified_and_audited",
        [AuditEventType.RoleRemoved] = "Services.RoleAssignmentServiceTests.Removing_a_role_ends_every_session_of_that_user_at_once_and_is_audited",
        [AuditEventType.RegistrationDuplicate] = Trail,
        [AuditEventType.AuthorizationCodeIssued] = "Api.OAuthApiTests.The_full_flow_issues_app_tokens_that_refresh_and_detect_reuse_and_never_unlock_this_API",
        [AuditEventType.AuthorizationCodeRedeemed] = "Api.OAuthApiTests.The_full_flow_issues_app_tokens_that_refresh_and_detect_reuse_and_never_unlock_this_API",
        [AuditEventType.AuthorizationCodeRejected] = "Api.OAuthApiTests.Codes_verifiers_and_tokens_never_reach_logs_or_audit_rows",
        [AuditEventType.AppCreated] = "Services.ClientApplicationRegistryTests.Created_applications_are_audited_listed_and_their_ids_and_audiences_are_unique",
        [AuditEventType.AppUpdated] = "Services.ClientApplicationRegistryTests.The_CORS_list_follows_the_registry_at_once_on_this_instance",
        [AuditEventType.AppDeactivated] = "Services.ClientApplicationRegistryTests.Deactivation_ends_the_applications_sessions_and_it_cannot_get_new_tokens",
        [AuditEventType.RolePermissionRemoved] = "Services.RoleAssignmentServiceTests.Removing_a_permission_from_a_role_ends_the_sessions_of_every_holder_only",
    };

    public static TheoryData<AuditEventType> AllTypes()
    {
        TheoryData<AuditEventType> data = new();
        foreach (AuditEventType type in Enum.GetValues<AuditEventType>())
        {
            data.Add(type);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(AllTypes))]
    public void Every_event_type_is_reserved_or_covered_by_a_persisted_row_test(AuditEventType type)
    {
        AuditEventSpec spec = AuditCatalogue.Events[type];
        if (spec.Reserved)
        {
            Assert.False(CoveredBy.ContainsKey(type), type + " is reserved but mapped to a test; mark it written in the catalogue");
            return;
        }

        Assert.True(CoveredBy.TryGetValue(type, out string? test), type + " is written but no test covers its persisted row");
        int split = test!.LastIndexOf('.');
        Type? owner = typeof(AuditCoverageTests).Assembly.GetType("Auth.IntegrationTests." + test[..split]);
        MethodInfo? method = owner?.GetMethod(test[(split + 1)..]);
        Assert.True(method is not null, test + " does not exist");
        Assert.True(method!.GetCustomAttributes<FactAttribute>().Any(), test + " is not a test");
    }
}
