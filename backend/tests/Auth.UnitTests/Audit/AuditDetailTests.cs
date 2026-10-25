using Auth.Contracts;
using Auth.Services.Audit;

namespace Auth.UnitTests.Audit;

/// <summary>T17: the central redaction of audit detail JSON (allow-listed keys, safe values only).</summary>
public class AuditDetailTests
{
    [Fact]
    public void Factories_render_compact_json_with_their_catalogue_keys()
    {
        Guid session = Guid.Parse("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
        DateTime until = new(2026, 10, 25, 12, 30, 0, DateTimeKind.Utc);

        Assert.Equal("""{"reason":"wrong_password"}""", AuditDetail.Render(AuditEvents.LoginFailed(null, "wrong_password")));
        Assert.Equal("""{"until":"2026-10-25T12:30:00.0000000Z","level":2}""", AuditDetail.Render(AuditEvents.Lockout(Guid.NewGuid(), until, 2)));
        Assert.Equal("""{"session":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","reason":"session_cap"}""", AuditDetail.Render(AuditEvents.SessionRevoked(Guid.NewGuid(), session, "session_cap")));
        Assert.Equal("""{"fields":["displayName","email","password"]}""", AuditDetail.Render(AuditEvents.RegistrationRejected(["password", "email", "displayName"])));
        Assert.Null(AuditDetail.Render(AuditEvents.TokenRefreshed(Guid.NewGuid())));
    }

    [Theory]
    [InlineData("hunter2-Violet-7319")]
    [InlineData("q2V7nYx0Rk3sJ9bT4uLmW8cZ1aP6dE5fG0hI2jK7lMn")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA")]
    [InlineData("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln")]
    [InlineData("wrong password")]
    [InlineData("Wrong_Password")]
    public void A_string_that_is_not_a_catalogue_word_is_never_written(string value)
    {
        string detail = AuditDetail.Render(AuditEvents.LoginFailed(null, value))!;
        string fields = AuditDetail.Render(AuditEvents.RegistrationRejected([value, "email"]))!;

        Assert.Equal("""{"reason":"[redacted]"}""", detail);
        Assert.DoesNotContain(value, fields, StringComparison.Ordinal);
        Assert.Contains("\"[redacted]\"", fields, StringComparison.Ordinal);
        Assert.Contains("\"email\"", fields, StringComparison.Ordinal);
    }

    [Fact]
    public void Keys_outside_the_catalogue_and_unsafe_value_types_are_dropped_or_redacted()
    {
        AuditEvent smuggled = new(
            AuditEventType.LoginFailed,
            null,
            new AuditField("reason", "locked"),
            new AuditField("password", "hunter2"),
            new AuditField("token", "abc"));
        AuditEvent local = new(AuditEventType.Lockout, null, new AuditField("until", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Local)), new AuditField("level", new object()));

        Assert.Equal("""{"reason":"locked"}""", AuditDetail.Render(smuggled));
        Assert.Equal("""{"until":"[redacted]","level":"[redacted]"}""", AuditDetail.Render(local));
        Assert.Null(AuditDetail.Render(new AuditEvent(AuditEventType.EmailVerified, null, new AuditField("password", "hunter2"))));
    }

    [Fact]
    public void Every_event_type_is_in_the_catalogue_and_high_volume_types_are_the_agreed_ones()
    {
        Assert.All(Enum.GetValues<AuditEventType>(), type => Assert.True(AuditCatalogue.Events.ContainsKey(type), type + " is missing from the catalogue"));
        Assert.Equal(
            ["EmailVerificationFailed", "LoginFailed", "PasswordResetRequested", "RefreshRejected", "RegistrationDuplicate", "RegistrationRejected", "TokenRefreshed"],
            AuditCatalogue.HighVolumeEventNames);
    }

    [Fact]
    public void Only_the_audit_service_writes_audit_rows()
    {
        Type[] writers = [.. typeof(IAuditService).Assembly.GetTypes()
            .Where(t => t.GetConstructors(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)
                .Any(c => c.GetParameters().Any(p => p.ParameterType == typeof(Auth.DAL.Repositories.IAuditLogRepository))))];

        Assert.Equal([typeof(AuditService)], writers);
    }

    [Fact]
    public void Reserved_types_have_no_factory_and_every_written_type_has_one_named_after_it()
    {
        HashSet<string> factories = [.. typeof(AuditEvents).GetMethods().Where(m => m.IsStatic && m.ReturnType == typeof(AuditEvent)).Select(m => m.Name)];

        foreach ((AuditEventType type, AuditEventSpec spec) in AuditCatalogue.Events)
        {
            Assert.True(spec.Reserved != factories.Contains(type.ToString()), type + ": reserved=" + spec.Reserved);
        }
    }
}
