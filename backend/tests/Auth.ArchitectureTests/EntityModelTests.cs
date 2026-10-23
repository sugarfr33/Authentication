using System.Reflection;

namespace Auth.ArchitectureTests;

/// <summary>Entity rules (T02 acceptance): one singular class per table, plain POCOs, single tenant.</summary>
public class EntityModelTests
{
    private static readonly string[] TableNames =
    [
        "User", "Role", "UserRole", "Permission", "RolePermission", "ClientApplication", "RefreshToken",
        "PasswordResetToken", "EmailVerificationToken", "AuditLog", "SigningKey", "MfaRecoveryCode",
    ];

    private static readonly string[] PersistenceAttributeNamespaces =
    [
        "System.ComponentModel.DataAnnotations",
        "Microsoft.EntityFrameworkCore",
    ];

    [Fact]
    public void Entity_classes_are_exactly_the_twelve_table_names()
    {
        IEnumerable<string> actual = EntityTypes().Select(t => t.Name);

        Assert.Equal(TableNames.Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Entity_class_names_are_singular()
    {
        IEnumerable<string> plural = EntityTypes()
            .Select(t => t.Name)
            .Where(n => n.EndsWith('s'));

        Assert.Empty(plural);
    }

    [Theory]
    [InlineData("FamilyId", typeof(Guid))]
    [InlineData("TokenHash", typeof(byte[]))]
    [InlineData("ExpiresUtc", typeof(DateTime))]
    [InlineData("RevokedUtc", typeof(DateTime?))]
    [InlineData("RevokedReason", typeof(string))]
    [InlineData("ReplacedByTokenId", typeof(Guid?))]
    [InlineData("IpAddress", typeof(string))]
    [InlineData("UserAgent", typeof(string))]
    public void RefreshToken_has_rotation_and_session_columns(string propertyName, Type expectedType)
    {
        PropertyInfo? property = typeof(Auth.Entities.RefreshToken).GetProperty(propertyName);

        Assert.NotNull(property);
        Assert.Equal(expectedType, property.PropertyType);
    }

    [Fact]
    public void Entities_have_no_persistence_attributes()
    {
        IEnumerable<string> offenders = EntityTypes()
            .SelectMany(t => new MemberInfo[] { t }.Concat(t.GetProperties()))
            .Where(m => m.CustomAttributes.Any(a => IsPersistenceAttribute(a.AttributeType)))
            .Select(m => m.DeclaringType is null ? m.Name : m.DeclaringType.Name + "." + m.Name);

        Assert.Empty(offenders);
    }

    [Fact]
    public void Entities_have_no_tenant_columns()
    {
        IEnumerable<string> offenders = EntityTypes()
            .SelectMany(t => t.GetProperties().Select(p => t.Name + "." + p.Name))
            .Where(n => n.Contains("Tenant", StringComparison.OrdinalIgnoreCase));

        Assert.Empty(offenders);
    }

    /// <summary>Entities are the instantiable public classes; static classes hold allowed-value constants.</summary>
    private static IEnumerable<Type> EntityTypes() =>
        typeof(Auth.Entities.AssemblyMarker).Assembly.GetExportedTypes()
            .Where(t => t.IsClass && !t.IsAbstract);

    private static bool IsPersistenceAttribute(Type attributeType) =>
        PersistenceAttributeNamespaces.Any(ns => (attributeType.Namespace ?? string.Empty).StartsWith(ns, StringComparison.Ordinal));
}
