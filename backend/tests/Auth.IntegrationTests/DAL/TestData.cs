using System.Security.Cryptography;
using Auth.Entities;

namespace Auth.IntegrationTests.DAL;

/// <summary>Valid entities with unique keys and values, so tests sharing one database never collide.</summary>
internal static class TestData
{
    public static readonly DateTime Now = new(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);

    public static byte[] Hash() => RandomNumberGenerator.GetBytes(32);

    public static User User()
    {
        string email = "user-" + Guid.NewGuid().ToString("N") + "@example.test";
        return new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            PasswordHash = "argon2id$placeholder",
            DisplayName = "Test User",
            IsActive = true,
            SecurityStamp = Guid.NewGuid(),
            CreatedUtc = Now,
            UpdatedUtc = Now,
        };
    }

    public static ClientApplication ClientApplication(bool isActive = true)
    {
        string clientId = "app-" + Guid.NewGuid().ToString("N");
        return new()
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            Name = "Test App",
            Audience = "api://" + clientId,
            AllowedOrigin = "[\"https://app.example.test\"]",
            RedirectUri = "[\"https://app.example.test/callback\"]",
            PostLogoutRedirectUri = "[]",
            IsActive = isActive,
            CreatedUtc = Now,
            UpdatedUtc = Now,
        };
    }

    public static Role Role(Guid? clientApplicationId = null)
    {
        string name = "role-" + Guid.NewGuid().ToString("N");
        return new Role { Id = Guid.NewGuid(), ClientApplicationId = clientApplicationId, Name = name, NormalizedName = name.ToUpperInvariant() };
    }

    public static Permission Permission(string? code = null) =>
        new() { Id = Guid.NewGuid(), Code = code ?? "perm." + Guid.NewGuid().ToString("N") };

    public static RefreshToken RefreshToken(Guid userId, Guid? familyId = null, DateTime? expiresUtc = null, DateTime? createdUtc = null) => new()
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        FamilyId = familyId ?? Guid.NewGuid(),
        TokenHash = Hash(),
        CreatedUtc = createdUtc ?? Now,
        ExpiresUtc = expiresUtc ?? Now.AddDays(14),
        IpAddress = "203.0.113.7",
        UserAgent = "IntegrationTests",
    };

    public static PasswordResetToken PasswordResetToken(Guid userId) => new()
    {
        Id = Guid.NewGuid(), UserId = userId, TokenHash = Hash(), CreatedUtc = Now, ExpiresUtc = Now.AddMinutes(15), RequestIp = "203.0.113.7",
    };

    public static EmailVerificationToken EmailVerificationToken(Guid userId) => new()
    {
        Id = Guid.NewGuid(), UserId = userId, TokenHash = Hash(), CreatedUtc = Now, ExpiresUtc = Now.AddHours(24),
    };

    public static MfaRecoveryCode MfaRecoveryCode(Guid userId) => new()
    {
        Id = Guid.NewGuid(), UserId = userId, CodeHash = Hash(), CreatedUtc = Now,
    };

    public static SigningKey SigningKey(string status, DateTime? activatedUtc = null) => new()
    {
        Id = Guid.NewGuid(),
        Kid = "kid-" + Guid.NewGuid().ToString("N"),
        Algorithm = SigningKeyAlgorithm.ES256,
        PublicKeyJwk = "{}",
        PrivateKeyReference = "secret-store/test",
        Status = status,
        CreatedUtc = Now,
        ActivatedUtc = activatedUtc,
    };

    public static AuditLog AuditLog(Guid? userId) => new()
    {
        OccurredUtc = Now, EventType = "LoginSucceeded", UserId = userId, IpAddress = "203.0.113.7",
    };
}
