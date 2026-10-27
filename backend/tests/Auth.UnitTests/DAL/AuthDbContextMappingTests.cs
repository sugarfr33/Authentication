using System.Reflection;
using Auth.DAL;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Auth.UnitTests.DAL;

/// <summary>
/// T03 mapping checks against the design-time EF model (no database): every one of the 12 tables is checked for
/// schema, columns (store type and nullability), keys, foreign keys, indexes, check and default constraints.
/// </summary>
public class AuthDbContextMappingTests
{
    private const string Schema = "auth";

    private static readonly IModel Model = CreateModel();

    private static readonly Dictionary<string, string[]> ExpectedColumns = new()
    {
        ["AuthorizationCode"] =
        [
            "Id uniqueidentifier", "CodeHash binary(32)", "UserId uniqueidentifier", "ClientApplicationId uniqueidentifier",
            "RedirectUri nvarchar(512)", "CodeChallenge varchar(128)", "CreatedUtc datetime2(7)", "ExpiresUtc datetime2(7)",
            "UsedUtc datetime2(7) NULL", "FamilyId uniqueidentifier NULL",
        ],
        ["User"] =
        [
            "Id uniqueidentifier", "Email nvarchar(256)", "NormalizedEmail nvarchar(256)", "EmailVerified bit",
            "PasswordHash nvarchar(512)", "DisplayName nvarchar(128)", "IsActive bit", "FailedLoginCount int",
            "LockoutEndUtc datetime2(7) NULL", "LockoutLevel int", "MfaEnabled bit", "MfaSecretEncrypted varbinary(256) NULL",
            "SecurityStamp uniqueidentifier", "CreatedUtc datetime2(7)", "UpdatedUtc datetime2(7)",
            "LastLoginUtc datetime2(7) NULL", "RowVersion rowversion",
        ],
        ["Role"] =
        [
            "Id uniqueidentifier", "ClientApplicationId uniqueidentifier NULL", "Name nvarchar(64)",
            "NormalizedName nvarchar(64)", "Description nvarchar(256) NULL", "IsSystem bit",
        ],
        ["UserRole"] = ["UserId uniqueidentifier", "RoleId uniqueidentifier", "AssignedUtc datetime2(7)"],
        ["Permission"] = ["Id uniqueidentifier", "Code nvarchar(128)", "Description nvarchar(256) NULL"],
        ["RolePermission"] = ["RoleId uniqueidentifier", "PermissionId uniqueidentifier"],
        ["ClientApplication"] =
        [
            "Id uniqueidentifier", "ClientId nvarchar(100)", "Name nvarchar(128)", "Audience nvarchar(256)",
            "AllowedOrigins nvarchar(max)", "RedirectUris nvarchar(max)", "PostLogoutRedirectUris nvarchar(max)",
            "RequireRole bit", "IsActive bit", "CreatedUtc datetime2(7)", "UpdatedUtc datetime2(7)",
        ],
        ["RefreshToken"] =
        [
            "Id uniqueidentifier", "UserId uniqueidentifier", "ClientApplicationId uniqueidentifier NULL",
            "FamilyId uniqueidentifier", "TokenHash binary(32)", "CreatedUtc datetime2(7)", "ExpiresUtc datetime2(7)",
            "RevokedUtc datetime2(7) NULL", "RevokedReason nvarchar(32) NULL", "ReplacedByTokenId uniqueidentifier NULL",
            "IpAddress nvarchar(45)", "UserAgent nvarchar(512)", "RowVersion rowversion",
        ],
        ["PasswordResetToken"] =
        [
            "Id uniqueidentifier", "UserId uniqueidentifier", "TokenHash binary(32)", "CreatedUtc datetime2(7)",
            "ExpiresUtc datetime2(7)", "UsedUtc datetime2(7) NULL", "RequestIp nvarchar(45)",
        ],
        ["EmailVerificationToken"] =
        [
            "Id uniqueidentifier", "UserId uniqueidentifier", "TokenHash binary(32)", "CreatedUtc datetime2(7)",
            "ExpiresUtc datetime2(7)", "UsedUtc datetime2(7) NULL", "PendingPasswordHash nvarchar(512) NULL",
            "PendingDisplayName nvarchar(128) NULL",
        ],
        ["AuditLog"] =
        [
            "Id bigint", "OccurredUtc datetime2(7)", "EventType nvarchar(64)", "UserId uniqueidentifier NULL",
            "ClientApplicationId uniqueidentifier NULL", "IpAddress nvarchar(45) NULL", "UserAgent nvarchar(512) NULL",
            "Detail nvarchar(2000) NULL", "CorrelationId nvarchar(64) NULL",
        ],
        ["SigningKey"] =
        [
            "Id uniqueidentifier", "Kid nvarchar(64)", "Algorithm nvarchar(10)", "PublicKeyJwk nvarchar(max)",
            "PrivateKeyReference nvarchar(256)", "Status nvarchar(16)", "CreatedUtc datetime2(7)",
            "ActivatedUtc datetime2(7) NULL", "RetireAfterUtc datetime2(7) NULL",
        ],
        ["MfaRecoveryCode"] =
        [
            "Id uniqueidentifier", "UserId uniqueidentifier", "CodeHash binary(32)", "CreatedUtc datetime2(7)",
            "UsedUtc datetime2(7) NULL",
        ],
    };

    private static readonly Dictionary<string, string> ExpectedPrimaryKeys = new()
    {
        ["User"] = "PK_User (Id)",
        ["Role"] = "PK_Role (Id)",
        ["UserRole"] = "PK_UserRole (UserId, RoleId)",
        ["Permission"] = "PK_Permission (Id)",
        ["RolePermission"] = "PK_RolePermission (RoleId, PermissionId)",
        ["ClientApplication"] = "PK_ClientApplication (Id)",
        ["RefreshToken"] = "PK_RefreshToken (Id)",
        ["PasswordResetToken"] = "PK_PasswordResetToken (Id)",
        ["EmailVerificationToken"] = "PK_EmailVerificationToken (Id)",
        ["AuditLog"] = "PK_AuditLog (Id)",
        ["SigningKey"] = "PK_SigningKey (Id)",
        ["MfaRecoveryCode"] = "PK_MfaRecoveryCode (Id)",
        ["AuthorizationCode"] = "PK_AuthorizationCode (Id)",
    };

    private static readonly Dictionary<string, string[]> ExpectedForeignKeys = new()
    {
        ["User"] = [],
        ["Role"] = ["FK_Role_ClientApplication_ClientApplicationId (ClientApplicationId) -> ClientApplication (Id) Restrict"],
        ["UserRole"] =
        [
            "FK_UserRole_User_UserId (UserId) -> User (Id) Cascade",
            "FK_UserRole_Role_RoleId (RoleId) -> Role (Id) Cascade",
        ],
        ["Permission"] = [],
        ["RolePermission"] =
        [
            "FK_RolePermission_Role_RoleId (RoleId) -> Role (Id) Cascade",
            "FK_RolePermission_Permission_PermissionId (PermissionId) -> Permission (Id) Cascade",
        ],
        ["ClientApplication"] = [],
        ["RefreshToken"] =
        [
            "FK_RefreshToken_User_UserId (UserId) -> User (Id) Cascade",
            "FK_RefreshToken_ClientApplication_ClientApplicationId (ClientApplicationId) -> ClientApplication (Id) Restrict",
            "FK_RefreshToken_RefreshToken_ReplacedByTokenId (ReplacedByTokenId) -> RefreshToken (Id) NoAction",
        ],
        ["PasswordResetToken"] = ["FK_PasswordResetToken_User_UserId (UserId) -> User (Id) Cascade"],
        ["EmailVerificationToken"] = ["FK_EmailVerificationToken_User_UserId (UserId) -> User (Id) Cascade"],
        ["AuditLog"] =
        [
            "FK_AuditLog_User_UserId (UserId) -> User (Id) SetNull",
            "FK_AuditLog_ClientApplication_ClientApplicationId (ClientApplicationId) -> ClientApplication (Id) SetNull",
        ],
        ["SigningKey"] = [],
        ["MfaRecoveryCode"] = ["FK_MfaRecoveryCode_User_UserId (UserId) -> User (Id) Cascade"],
        ["AuthorizationCode"] =
        [
            "FK_AuthorizationCode_User_UserId (UserId) -> User (Id) Cascade",
            "FK_AuthorizationCode_ClientApplication_ClientApplicationId (ClientApplicationId) -> ClientApplication (Id) Restrict",
        ],
    };

    private static readonly Dictionary<string, string[]> ExpectedIndexes = new()
    {
        ["User"] = ["UQ_User_NormalizedEmail UNIQUE (NormalizedEmail)"],
        ["Role"] =
        [
            "UQ_Role_ClientApplicationId_NormalizedName UNIQUE (ClientApplicationId, NormalizedName)",
            "IX_Role_ClientApplicationId (ClientApplicationId)",
        ],
        ["UserRole"] = ["IX_UserRole_RoleId (RoleId)"],
        ["Permission"] = ["UQ_Permission_Code UNIQUE (Code)"],
        ["RolePermission"] = ["IX_RolePermission_PermissionId (PermissionId)"],
        ["ClientApplication"] = ["UQ_ClientApplication_ClientId UNIQUE (ClientId)", "UQ_ClientApplication_Audience UNIQUE (Audience)"],
        ["RefreshToken"] =
        [
            "UQ_RefreshToken_TokenHash UNIQUE (TokenHash)",
            "IX_RefreshToken_FamilyId (FamilyId)",
            "IX_RefreshToken_ExpiresUtc (ExpiresUtc)",
            "IX_RefreshToken_UserId_RevokedUtc (UserId, RevokedUtc)",
            "IX_RefreshToken_ClientApplicationId (ClientApplicationId)",
            "IX_RefreshToken_ReplacedByTokenId (ReplacedByTokenId)",
        ],
        ["PasswordResetToken"] =
        [
            "UQ_PasswordResetToken_TokenHash UNIQUE (TokenHash)",
            "IX_PasswordResetToken_UserId (UserId)",
            "IX_PasswordResetToken_ExpiresUtc (ExpiresUtc)",
        ],
        ["EmailVerificationToken"] =
        [
            "UQ_EmailVerificationToken_TokenHash UNIQUE (TokenHash)",
            "IX_EmailVerificationToken_UserId (UserId)",
            "IX_EmailVerificationToken_ExpiresUtc (ExpiresUtc)",
        ],
        ["AuditLog"] =
        [
            "IX_AuditLog_UserId_OccurredUtc (UserId, OccurredUtc)",
            "IX_AuditLog_EventType_OccurredUtc (EventType, OccurredUtc)",
            "IX_AuditLog_ClientApplicationId (ClientApplicationId)",
        ],
        ["SigningKey"] = ["UQ_SigningKey_Kid UNIQUE (Kid)", "IX_SigningKey_Status (Status)"],
        ["MfaRecoveryCode"] = ["IX_MfaRecoveryCode_UserId (UserId)"],
        ["AuthorizationCode"] =
        [
            "UQ_AuthorizationCode_CodeHash UNIQUE (CodeHash)",
            "IX_AuthorizationCode_ExpiresUtc (ExpiresUtc)",
            "IX_AuthorizationCode_ClientApplicationId (ClientApplicationId)",
            "IX_AuthorizationCode_UserId (UserId)",
        ],
    };

    private static readonly Dictionary<string, string[]> ExpectedCheckConstraints = new()
    {
        ["User"] = [],
        ["Role"] =
        [
            "CK_Role_GlobalName_NotApplicationPrefix: [ClientApplicationId] IS NOT NULL OR (UPPER(LTRIM([Name])) NOT LIKE N'APP:%' AND UPPER(LTRIM([NormalizedName])) NOT LIKE N'APP:%')",
        ],
        ["UserRole"] = [],
        ["Permission"] = [],
        ["RolePermission"] = [],
        ["ClientApplication"] =
        [
            "CK_ClientApplication_AllowedOrigins_IsJsonArray: ISJSON([AllowedOrigins]) = 1 AND LEFT(LTRIM([AllowedOrigins]), 1) = N'['",
            "CK_ClientApplication_PostLogoutRedirectUris_IsJsonArray: ISJSON([PostLogoutRedirectUris]) = 1 AND LEFT(LTRIM([PostLogoutRedirectUris]), 1) = N'['",
            "CK_ClientApplication_RedirectUris_IsJsonArray: ISJSON([RedirectUris]) = 1 AND LEFT(LTRIM([RedirectUris]), 1) = N'['",
        ],
        ["RefreshToken"] =
        [
            "CK_RefreshToken_Expiry: [ExpiresUtc] > [CreatedUtc]",
            "CK_RefreshToken_RevokedReason: [RevokedReason] IS NULL OR [RevokedReason] IN "
                + "(N'Rotated', N'Reuse', N'Logout', N'LogoutAll', N'PasswordChange', N'Admin')",
        ],
        ["PasswordResetToken"] = [],
        ["EmailVerificationToken"] = [],
        ["AuditLog"] = [],
        ["SigningKey"] =
        [
            "CK_SigningKey_Status: [Status] IN (N'Active', N'Retiring', N'Retired')",
            "CK_SigningKey_Algorithm: [Algorithm] IN (N'RS256', N'ES256')",
        ],
        ["MfaRecoveryCode"] = [],
        ["AuthorizationCode"] =
        [
            "CK_AuthorizationCode_Expiry: [ExpiresUtc] > [CreatedUtc]",
            "CK_AuthorizationCode_CodeChallenge_Length: LEN([CodeChallenge]) BETWEEN 43 AND 128",
        ],
    };

    private static readonly string[] ExpectedDefaults =
    [
        "DF_ClientApplication_RequireRole False",
        "DF_User_CreatedUtc sysutcdatetime()",
    ];

    public static TheoryData<string> TableNames => new(ExpectedColumns.Keys);

    [Fact]
    public void Model_maps_exactly_the_thirteen_tables_in_the_auth_schema()
    {
        IEnumerable<string> tables = Model.GetRelationalModel().Tables.Select(t => t.Schema + "." + t.Name);

        Assert.Equal(ExpectedColumns.Keys.Select(n => Schema + "." + n).Order(StringComparer.Ordinal), tables.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Entity_maps_to_singular_table_of_the_same_name(string tableName)
    {
        IEntityType entity = Assert.Single(Model.GetEntityTypes(), e => e.ClrType.Name == tableName);

        Assert.Equal(tableName, entity.GetTableName());
        Assert.Equal(Schema, entity.GetSchema());
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Columns_have_the_planned_store_types_and_nullability(string tableName)
    {
        IEnumerable<string> actual = Table(tableName).Columns
            .Select(c => c.Name + " " + c.StoreType + (c.IsNullable ? " NULL" : string.Empty));

        Assert.Equal(ExpectedColumns[tableName].Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Primary_key_is_named_and_keyed_as_planned(string tableName)
    {
        IPrimaryKeyConstraint? key = Table(tableName).PrimaryKey;

        Assert.NotNull(key);
        Assert.Equal(ExpectedPrimaryKeys[tableName], key.Name + " (" + ColumnList(key.Columns) + ")");
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Foreign_keys_are_named_and_cascade_as_planned(string tableName)
    {
        IEnumerable<string> actual = Table(tableName).ForeignKeyConstraints.Select(fk =>
            fk.Name + " (" + ColumnList(fk.Columns) + ") -> " + fk.PrincipalTable.Name
            + " (" + ColumnList(fk.PrincipalColumns) + ") " + fk.OnDeleteAction);

        Assert.Equal(ExpectedForeignKeys[tableName].Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Indexes_are_named_as_planned_and_unfiltered(string tableName)
    {
        IEnumerable<string> actual = Table(tableName).Indexes.Select(ix =>
            ix.Name + (ix.IsUnique ? " UNIQUE" : string.Empty) + " (" + ColumnList(ix.Columns) + ")"
            + (ix.Filter is null ? string.Empty : " WHERE " + ix.Filter));

        Assert.Equal(ExpectedIndexes[tableName].Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Check_constraints_are_named_as_planned(string tableName)
    {
        IEnumerable<string> actual = Table(tableName).CheckConstraints.Select(ck => ck.Name + ": " + ck.Sql);

        Assert.Equal(ExpectedCheckConstraints[tableName].Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(TableNames))]
    public void Constraint_names_follow_the_plan_patterns(string tableName)
    {
        ITable table = Table(tableName);
        List<string> violations = [];

        if (table.PrimaryKey?.Name != "PK_" + tableName)
        {
            violations.Add("PK " + table.PrimaryKey?.Name);
        }

        violations.AddRange(table.ForeignKeyConstraints
            .Where(fk => fk.Name != "FK_" + tableName + "_" + fk.PrincipalTable.Name + "_" + ColumnList(fk.Columns, "_"))
            .Select(fk => "FK " + fk.Name));

        violations.AddRange(table.Indexes
            .Where(ix => ix.Name != (ix.IsUnique ? "UQ_" : "IX_") + tableName + "_" + ColumnList(ix.Columns, "_"))
            .Select(ix => "Index " + ix.Name));

        violations.AddRange(table.CheckConstraints
            .Where(ck => !(ck.Name ?? string.Empty).StartsWith("CK_" + tableName + "_", StringComparison.Ordinal))
            .Select(ck => "Check " + ck.Name));

        violations.AddRange(table.Columns
            .Where(c => HasDefault(c) && DefaultConstraintName(table, c) != "DF_" + tableName + "_" + c.Name)
            .Select(c => "Default " + DefaultConstraintName(table, c)));

        Assert.Empty(violations);
    }

    [Fact]
    public void Only_planned_columns_have_database_defaults()
    {
        IEnumerable<string> actual = Model.GetRelationalModel().Tables
            .SelectMany(t => t.Columns.Where(HasDefault).Select(c =>
                DefaultConstraintName(t, c) + " " + (c.DefaultValueSql ?? Convert.ToString(c.DefaultValue, System.Globalization.CultureInfo.InvariantCulture))));

        Assert.Equal(
            ExpectedDefaults,
            actual.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("User")]
    [InlineData("RefreshToken")]
    public void RowVersion_is_the_concurrency_token(string entityName)
    {
        IProperty property = Property(entityName, "RowVersion");

        Assert.True(property.IsConcurrencyToken);
        Assert.Equal(ValueGenerated.OnAddOrUpdate, property.ValueGenerated);
    }

    [Fact]
    public void Only_User_and_RefreshToken_use_optimistic_concurrency()
    {
        IEnumerable<string> tokens = Model.GetEntityTypes()
            .SelectMany(e => e.GetProperties().Where(p => p.IsConcurrencyToken).Select(p => e.ClrType.Name + "." + p.Name));

        Assert.Equal(["RefreshToken.RowVersion", "User.RowVersion"], tokens.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void AuditLog_key_is_a_bigint_identity()
    {
        IProperty id = Property("AuditLog", "Id");

        Assert.Equal(Microsoft.EntityFrameworkCore.Metadata.SqlServerValueGenerationStrategy.IdentityColumn, id.GetValueGenerationStrategy());
    }

    [Fact]
    public void DbSet_properties_are_singular_and_named_after_their_table()
    {
        IEnumerable<string> mismatches = typeof(AuthDbContext)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>))
            .Select(p => p.Name + "=" + p.PropertyType.GetGenericArguments()[0].Name)
            .Where(pair => pair.Split('=')[0] != pair.Split('=')[1]);

        int count = typeof(AuthDbContext).GetProperties().Count(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>));

        Assert.Empty(mismatches);
        Assert.Equal(13, count);
    }

    [Fact]
    public void Create_script_creates_every_table_in_the_auth_schema()
    {
        using AuthDbContext context = CreateContext();
        string script = context.Database.GenerateCreateScript();

        Assert.All(ExpectedColumns.Keys, name => Assert.Contains("CREATE TABLE [auth].[" + name + "]", script, StringComparison.Ordinal));
    }

    [Fact]
    public void Design_time_factory_builds_a_SQL_Server_context()
    {
        using AuthDbContext context = new AuthDbContextFactory().CreateDbContext([]);

        Assert.Equal("Microsoft.EntityFrameworkCore.SqlServer", context.Database.ProviderName);
    }

    private static AuthDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer("Server=unused;Database=unused").Options);

    private static IModel CreateModel()
    {
        using AuthDbContext context = CreateContext();
        return context.GetService<IDesignTimeModel>().Model;
    }

    private static ITable Table(string name) =>
        Model.GetRelationalModel().FindTable(name, Schema) ?? throw new InvalidOperationException("Table not mapped: " + name);

    private static IProperty Property(string entityName, string propertyName)
    {
        IEntityType entity = Model.GetEntityTypes().Single(e => e.ClrType.Name == entityName);
        return entity.FindProperty(propertyName) ?? throw new InvalidOperationException(entityName + "." + propertyName);
    }

    private static string ColumnList(IEnumerable<IColumn> columns, string separator = ", ") =>
        string.Join(separator, columns.Select(c => c.Name));

    private static bool HasDefault(IColumn column) => column.DefaultValueSql is not null || column.DefaultValue is not null;

    private static string? DefaultConstraintName(ITable table, IColumn column) =>
        column.PropertyMappings[0].Property.GetDefaultConstraintName(StoreObjectIdentifier.Table(table.Name, table.Schema));
}
