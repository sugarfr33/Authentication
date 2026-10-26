using System.Text.RegularExpressions;
using Auth.DAL;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;

namespace Auth.IntegrationTests.DAL;

/// <summary>
/// T05 on real SQL Server: Up applies cleanly and a second run is a no-op, Down reverts, and the idempotent
/// docs script runs twice. Each test uses its own throwaway <c>CentralAuth_Migrations_run{id}_Test</c> database
/// (guarded by the _Test rule), created and dropped inside the test.
/// </summary>
[Collection(SqlServerTestGroup.Name)]
public partial class MigrationTests(SqlServerDatabaseFixture database) : IAsyncLifetime
{
    private static readonly string[] AllMigrations = ["20261024081023_InitialCreate", "20261024120957_EmailVerificationPendingRegistration", "20261025040727_RetentionAndAudienceIndexes", "20261025043218_AuthorizationCodes", "20261026095636_ClientApplicationListNames"];

    private static readonly string[] Tables =
    [
        "AuditLog", "AuthorizationCode", "ClientApplication", "EmailVerificationToken", "MfaRecoveryCode", "PasswordResetToken", "Permission",
        "RefreshToken", "Role", "RolePermission", "SigningKey", "User", "UserRole",
    ];

    private readonly string connectionString = TestDatabaseNames.WithUniqueDatabase(database.ConnectionString, "CentralAuth_Migrations");

    [Fact]
    public async Task Migrate_applies_cleanly_and_a_second_run_is_a_no_op()
    {
        await using AuthDbContext context = await FreshContextAsync(createEmptyDatabase: false);

        await context.Database.MigrateAsync();
        IReadOnlyList<string> schemaAfterFirst = await SchemaObjectsAsync();

        await context.Database.MigrateAsync();

        Assert.Equal(AllMigrations, await context.Database.GetAppliedMigrationsAsync());
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
        Assert.Equal(Tables.Append(AuthDbContext.MigrationsHistoryTable).Order(StringComparer.Ordinal), await AuthTablesAsync());
        Assert.Equal(schemaAfterFirst, await SchemaObjectsAsync());
        Assert.Equal(AllMigrations.Length, await HistoryRowCountAsync());
    }

    [Fact]
    public async Task Down_migration_reverts_everything_and_Up_can_be_reapplied()
    {
        await using AuthDbContext context = await FreshContextAsync(createEmptyDatabase: false);
        IMigrator migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync();
        IReadOnlyList<string> migrated = await SchemaObjectsAsync();

        await migrator.MigrateAsync(Migration.InitialDatabase);

        Assert.Equal([AuthDbContext.MigrationsHistoryTable], await AuthTablesAsync());
        Assert.Equal(0, await HistoryRowCountAsync());
        Assert.Empty(await context.Database.GetAppliedMigrationsAsync());

        await migrator.MigrateAsync();

        Assert.Equal(migrated, await SchemaObjectsAsync());
    }

    [Fact]
    public async Task Idempotent_docs_script_runs_twice_on_an_empty_database_and_matches_Migrate()
    {
        IReadOnlyList<string> viaMigrate;
        await using (AuthDbContext migrated = await FreshContextAsync(createEmptyDatabase: false))
        {
            await migrated.Database.MigrateAsync();
            viaMigrate = await SchemaObjectsAsync();
        }

        await using AuthDbContext context = await FreshContextAsync(createEmptyDatabase: true);
        string script = await File.ReadAllTextAsync(Path.Combine(RepoRoot(), "docs", "CentralAuth.initial.sql"));

        await ExecuteScriptAsync(script);
        await ExecuteScriptAsync(script);

        Assert.Equal(viaMigrate, await SchemaObjectsAsync());
        Assert.Equal(AllMigrations.Length, await HistoryRowCountAsync());
        Assert.Equal(AllMigrations, await context.Database.GetAppliedMigrationsAsync());
    }

    /// <summary>Drops any leftover copy, then optionally creates an empty database (no tables, no history).</summary>
    /// <summary>T18: the unique audience index refuses to apply over shared audiences instead of guessing.</summary>
    [Fact]
    public async Task The_audience_index_migration_stops_on_shared_audiences_and_applies_once_they_are_fixed()
    {
        await using AuthDbContext context = await FreshContextAsync(createEmptyDatabase: false);
        IMigrator migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync("20261024120957_EmailVerificationPendingRegistration");
        DateTime now = DateTime.UtcNow;
        await context.Database.ExecuteSqlAsync($"""
            INSERT INTO [auth].[ClientApplication] ([Id], [ClientId], [Name], [Audience], [AllowedOrigin], [RedirectUri], [PostLogoutRedirectUri], [RequirePkce], [IsActive], [CreatedUtc], [UpdatedUtc])
            VALUES ({Guid.NewGuid()}, N'first-app', N'First', N'api://shared', N'[]', N'[]', N'[]', 1, 1, {now}, {now}),
                   ({Guid.NewGuid()}, N'second-app', N'Second', N'api://shared', N'[]', N'[]', N'[]', 1, 1, {now}, {now})
            """);

        SqlException refused = await Assert.ThrowsAsync<SqlException>(() => migrator.MigrateAsync());
        await context.Database.ExecuteSqlAsync($"UPDATE [auth].[ClientApplication] SET [Audience] = N'api://second' WHERE [ClientId] = N'second-app'");
        await migrator.MigrateAsync();

        Assert.Contains("share an Audience", refused.Message, StringComparison.Ordinal);
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    /// <summary>T29: the list columns are renamed in place, so an existing application keeps every value; RequirePkce goes.</summary>
    [Fact]
    public async Task The_list_rename_migration_keeps_existing_applications_and_drops_RequirePkce()
    {
        await using AuthDbContext context = await FreshContextAsync(createEmptyDatabase: false);
        IMigrator migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync("20261025043218_AuthorizationCodes");
        Guid id = Guid.NewGuid();
        DateTime now = DateTime.UtcNow;
        await context.Database.ExecuteSqlAsync($"""
            INSERT INTO [auth].[ClientApplication] ([Id], [ClientId], [Name], [Audience], [AllowedOrigin], [RedirectUri], [PostLogoutRedirectUri], [RequirePkce], [IsActive], [CreatedUtc], [UpdatedUtc])
            VALUES ({id}, N'kept-app', N'Kept', N'api://kept', N'["https://kept.example.test"]', N'["https://kept.example.test/callback"]', N'["https://kept.example.test/"]', 1, 1, {now}, {now})
            """);

        await migrator.MigrateAsync();

        Assert.Equal(
            ["[\"https://kept.example.test\"]|[\"https://kept.example.test/callback\"]|[\"https://kept.example.test/\"]"],
            await QueryAsync("SELECT [AllowedOrigins] + N'|' + [RedirectUris] + N'|' + [PostLogoutRedirectUris] FROM [auth].[ClientApplication] WHERE [ClientId] = N'kept-app'"));
        Assert.Empty(await QueryAsync("SELECT c.name FROM sys.columns c WHERE c.object_id = OBJECT_ID(N'auth.ClientApplication') AND c.name IN (N'RequirePkce', N'AllowedOrigin', N'RedirectUri', N'PostLogoutRedirectUri')"));
        Assert.Contains(await QueryAsync("SELECT name FROM sys.check_constraints WHERE parent_object_id = OBJECT_ID(N'auth.ClientApplication')"), n => n == "CK_ClientApplication_AllowedOrigins_IsJsonArray");

        // The stricter CHECK refuses JSON that is not an array.
        await Assert.ThrowsAsync<SqlException>(() => context.Database.ExecuteSqlAsync($"UPDATE [auth].[ClientApplication] SET [AllowedOrigins] = N'{{}}' WHERE [Id] = {id}"));
    }

    /// <summary>T29: a list column holding JSON that is not an array stops the migration with a clear error, before any change.</summary>
    [Fact]
    public async Task The_list_rename_migration_stops_on_a_non_array_list_and_applies_once_it_is_fixed()
    {
        await using AuthDbContext context = await FreshContextAsync(createEmptyDatabase: false);
        IMigrator migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync("20261025043218_AuthorizationCodes");
        DateTime now = DateTime.UtcNow;
        string notAnArray = """{"origin":"https://odd.example.test"}""";
        await context.Database.ExecuteSqlAsync($"""
            INSERT INTO [auth].[ClientApplication] ([Id], [ClientId], [Name], [Audience], [AllowedOrigin], [RedirectUri], [PostLogoutRedirectUri], [RequirePkce], [IsActive], [CreatedUtc], [UpdatedUtc])
            VALUES ({Guid.NewGuid()}, N'odd-app', N'Odd', N'api://odd', {notAnArray}, N'[]', N'[]', 1, 1, {now}, {now})
            """);

        SqlException refused = await Assert.ThrowsAsync<SqlException>(() => migrator.MigrateAsync());
        Assert.Contains("is not a JSON array", refused.Message, StringComparison.Ordinal);
        Assert.Single(await QueryAsync("SELECT c.name FROM sys.columns c WHERE c.object_id = OBJECT_ID(N'auth.ClientApplication') AND c.name = N'AllowedOrigin'"));

        await context.Database.ExecuteSqlAsync($"UPDATE [auth].[ClientApplication] SET [AllowedOrigin] = N'[\"https://odd.example.test\"]' WHERE [ClientId] = N'odd-app'");
        await migrator.MigrateAsync();

        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    private async Task<AuthDbContext> FreshContextAsync(bool createEmptyDatabase)
    {
        SqlServerDatabaseFixture.EnsureThrowawayDatabase(connectionString);
        DbContextOptionsBuilder<AuthDbContext> builder = new();
        AuthDbContext.UseAuthSqlServer(builder, connectionString);
        AuthDbContext context = new(builder.Options);

        await context.Database.EnsureDeletedAsync();
        if (createEmptyDatabase)
        {
            await context.GetService<IRelationalDatabaseCreator>().CreateAsync();
        }

        return context;
    }

    public Task InitializeAsync() => Task.CompletedTask;

    /// <summary>Always drops the test database, even when the test failed.</summary>
    public async Task DisposeAsync()
    {
        SqlServerDatabaseFixture.EnsureThrowawayDatabase(connectionString);
        DbContextOptionsBuilder<AuthDbContext> builder = new();
        AuthDbContext.UseAuthSqlServer(builder, connectionString);
        await using AuthDbContext context = new(builder.Options);
        await context.Database.EnsureDeletedAsync();
    }

    /// <summary>Runs the script the way sqlcmd does: one batch per GO separator.</summary>
    private async Task ExecuteScriptAsync(string script)
    {
        await using SqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        foreach (string batch in GoSeparator().Split(script).Where(b => !string.IsNullOrWhiteSpace(b)))
        {
            await using SqlCommand command = new(batch, connection);
            await command.ExecuteNonQueryAsync();
        }
    }

    private async Task<List<string>> AuthTablesAsync()
    {
        List<string> tables = await QueryAsync("SELECT t.name FROM sys.tables t WHERE t.schema_id = SCHEMA_ID(N'auth')");
        tables.Sort(StringComparer.Ordinal);
        return tables;
    }

    /// <summary>Every table, column, key, index, check and default in the auth schema, with its type or definition.</summary>
    private async Task<IReadOnlyList<string>> SchemaObjectsAsync()
    {
        List<string> objects = await QueryAsync("""
            SELECT o.type_desc COLLATE DATABASE_DEFAULT + N' ' + o.name COLLATE DATABASE_DEFAULT + N' ON ' + ISNULL(OBJECT_NAME(o.parent_object_id), N'-') COLLATE DATABASE_DEFAULT
            FROM sys.objects o WHERE o.schema_id = SCHEMA_ID(N'auth') AND o.is_ms_shipped = 0
            UNION ALL
            SELECT N'INDEX ' + i.name COLLATE DATABASE_DEFAULT + N' ON ' + OBJECT_NAME(i.object_id) COLLATE DATABASE_DEFAULT + CASE WHEN i.is_unique = 1 THEN N' UNIQUE' ELSE N'' END
            FROM sys.indexes i JOIN sys.tables t ON t.object_id = i.object_id
            WHERE t.schema_id = SCHEMA_ID(N'auth') AND i.name IS NOT NULL
            UNION ALL
            SELECT N'COLUMN ' + t.name COLLATE DATABASE_DEFAULT + N'.' + c.name COLLATE DATABASE_DEFAULT + N' ' + TYPE_NAME(c.user_type_id) COLLATE DATABASE_DEFAULT + N'(' + CAST(c.max_length AS nvarchar(10)) + N')'
                + CASE WHEN c.is_nullable = 1 THEN N' NULL' ELSE N'' END
            FROM sys.columns c JOIN sys.tables t ON t.object_id = c.object_id
            WHERE t.schema_id = SCHEMA_ID(N'auth')
            """);
        objects.Sort(StringComparer.Ordinal);
        return objects;
    }

    private async Task<int> HistoryRowCountAsync() =>
        int.Parse((await QueryAsync("SELECT CAST(COUNT(*) AS nvarchar(10)) FROM [auth].[__EFMigrationsHistory]"))[0], System.Globalization.CultureInfo.InvariantCulture);

    private async Task<List<string>> QueryAsync(string sql)
    {
        await using SqlConnection connection = new(connectionString);
        await connection.OpenAsync();
        await using SqlCommand command = new(sql, connection);
        await using SqlDataReader reader = await command.ExecuteReaderAsync();
        List<string> rows = [];
        while (await reader.ReadAsync())
        {
            rows.Add(reader.GetString(0));
        }

        return rows;
    }

    private static string WithDatabase(string connectionString, string databaseName) =>
        new SqlConnectionStringBuilder(connectionString) { InitialCatalog = databaseName }.ConnectionString;

    private static string RepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "backend", "Auth.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found above " + AppContext.BaseDirectory);
    }

    [GeneratedRegex(@"^\s*GO\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex GoSeparator();
}
