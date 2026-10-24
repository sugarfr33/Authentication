using System.Text.RegularExpressions;
using Auth.DAL;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Auth.UnitTests.DAL;

/// <summary>
/// T05: docs/CentralAuth.initial.sql is the idempotent script of the current migrations, and every object it creates is
/// singular, in schema auth, and named by the plan patterns. No database needed (executing it is an integration test).
/// </summary>
public partial class MigrationScriptTests
{
    private static readonly string[] Tables =
    [
        "AuditLog", "ClientApplication", "EmailVerificationToken", "MfaRecoveryCode", "PasswordResetToken", "Permission",
        "RefreshToken", "Role", "RolePermission", "SigningKey", "User", "UserRole",
    ];

    private static readonly string ScriptPath = Path.Combine(FindRepoRoot(), "docs", "CentralAuth.initial.sql");

    [Fact]
    public void Docs_script_is_the_current_idempotent_migration_script()
    {
        using AuthDbContext context = CreateContext();
        string generated = context.GetService<IMigrator>().GenerateScript(options: MigrationsSqlGenerationOptions.Idempotent);

        Assert.Equal(Normalize(generated), Normalize(WithoutHeader(File.ReadAllText(ScriptPath))));
    }

    [Fact]
    public void Script_header_names_the_CentralAuth_database_and_has_no_USE_statement()
    {
        string script = File.ReadAllText(ScriptPath);

        Assert.Contains("-- Target database: CentralAuth, schema auth.", script, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"^\s*USE\s", RegexOptions.Multiline | RegexOptions.IgnoreCase), script);
    }

    [Fact]
    public void Script_creates_only_the_twelve_auth_tables_and_the_auth_migrations_history_table()
    {
        IEnumerable<string> created = CreateTablePattern().Matches(File.ReadAllText(ScriptPath))
            .Select(m => m.Groups["schema"].Value + "." + m.Groups["table"].Value)
            .Distinct();

        IEnumerable<string> expected = Tables.Append(AuthDbContext.MigrationsHistoryTable).Select(t => "auth." + t);
        Assert.Equal(expected.Order(StringComparer.Ordinal), created.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Script_object_names_are_singular_and_follow_the_plan_patterns()
    {
        string script = File.ReadAllText(ScriptPath);
        IEnumerable<string> constraints = ConstraintPattern().Matches(script).Select(m => m.Groups["name"].Value);
        IEnumerable<string> indexes = IndexPattern().Matches(script).Select(m => m.Groups["name"].Value);

        IEnumerable<string> offPattern = constraints.Concat(indexes)
            .Where(n => n != "PK___EFMigrationsHistory" && !PlanNamePattern().IsMatch(n));
        IEnumerable<string> pluralTables = CreateTablePattern().Matches(script)
            .Select(m => m.Groups["table"].Value)
            .Where(t => t.EndsWith('s') && t != "Status");

        Assert.NotEmpty(constraints);
        Assert.NotEmpty(indexes);
        Assert.Empty(offPattern);
        Assert.Empty(pluralTables);
    }

    [Fact]
    public void Script_targets_only_the_auth_schema()
    {
        IEnumerable<string> schemas = SchemaReferencePattern().Matches(File.ReadAllText(ScriptPath))
            .Select(m => m.Groups["schema"].Value)
            .Distinct();

        Assert.Equal(["auth"], schemas);
    }

    private static AuthDbContext CreateContext()
    {
        DbContextOptionsBuilder<AuthDbContext> builder = new();
        AuthDbContext.UseAuthSqlServer(builder, "Server=unused;Database=unused");
        return new AuthDbContext(builder.Options);
    }

    /// <summary>Drops the leading "--" comment block that documents the file.</summary>
    private static string WithoutHeader(string script) =>
        string.Join('\n', Normalize(script).Split('\n').SkipWhile(line => line.StartsWith("--", StringComparison.Ordinal) || line.Length == 0));

    private static string Normalize(string text) => text.TrimStart('﻿').Replace("\r\n", "\n", StringComparison.Ordinal).Trim();

    private static string FindRepoRoot() => Directory.GetParent(FindBackendRoot())!.FullName;

    private static string FindBackendRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Auth.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Auth.sln not found above " + AppContext.BaseDirectory);
    }

    [GeneratedRegex(@"CREATE TABLE \[(?<schema>[^\]]+)\]\.\[(?<table>[^\]]+)\]")]
    private static partial Regex CreateTablePattern();

    [GeneratedRegex(@"CONSTRAINT \[(?<name>[^\]]+)\]")]
    private static partial Regex ConstraintPattern();

    [GeneratedRegex(@"CREATE (?:UNIQUE )?INDEX \[(?<name>[^\]]+)\]")]
    private static partial Regex IndexPattern();

    [GeneratedRegex(@"^(PK|FK|IX|UQ|CK|DF)_[A-Za-z]+(_[A-Za-z]+)*$")]
    private static partial Regex PlanNamePattern();

    /// <summary>Every [schema].[object] reference in the script.</summary>
    [GeneratedRegex(@"\[(?<schema>[A-Za-z0-9_]+)\]\.\[[^\]]+\]")]
    private static partial Regex SchemaReferencePattern();
}
