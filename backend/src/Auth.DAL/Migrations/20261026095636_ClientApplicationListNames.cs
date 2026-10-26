using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.DAL.Migrations
{
    /// <summary>
    /// T29 (schema change approved by the human): the three list columns of auth.ClientApplication get plural names that
    /// match the API (they hold JSON arrays), their CHECKs require a JSON array instead of any JSON, and the unused
    /// RequirePkce column is dropped (every client is public and PKCE is always required in code).
    /// The columns are renamed in place with sp_rename, so existing rows keep their values.
    /// </summary>
    internal partial class ClientApplicationListNames : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Any error aborts and rolls back the whole batch (also when the idempotent script runs outside EF).
            migrationBuilder.Sql("SET XACT_ABORT ON;");

            // Refuse, with a clear message, rows the stricter CHECKs would reject. EXEC keeps the old column names out of
            // compilation, so the idempotent script still runs on a database where this migration is already applied.
            migrationBuilder.Sql(
                "EXEC(N'IF EXISTS (SELECT 1 FROM [auth].[ClientApplication] WHERE "
                + "ISJSON([AllowedOrigin]) = 0 OR LEFT(LTRIM([AllowedOrigin]), 1) <> N''['' OR "
                + "ISJSON([RedirectUri]) = 0 OR LEFT(LTRIM([RedirectUri]), 1) <> N''['' OR "
                + "ISJSON([PostLogoutRedirectUri]) = 0 OR LEFT(LTRIM([PostLogoutRedirectUri]), 1) <> N''['') "
                + "THROW 50029, ''A ClientApplication list column is not a JSON array; fix it before applying ClientApplicationListNames (see docs/client-applications.md).'', 1;');");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ClientApplication_AllowedOrigin_IsJson",
                schema: "auth",
                table: "ClientApplication");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ClientApplication_PostLogoutRedirectUri_IsJson",
                schema: "auth",
                table: "ClientApplication");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ClientApplication_RedirectUri_IsJson",
                schema: "auth",
                table: "ClientApplication");

            migrationBuilder.DropColumn(
                name: "RequirePkce",
                schema: "auth",
                table: "ClientApplication")
                .Annotation("Relational:DefaultConstraintName", "DF_ClientApplication_RequirePkce");

            migrationBuilder.RenameColumn(
                name: "RedirectUri",
                schema: "auth",
                table: "ClientApplication",
                newName: "RedirectUris");

            migrationBuilder.RenameColumn(
                name: "PostLogoutRedirectUri",
                schema: "auth",
                table: "ClientApplication",
                newName: "PostLogoutRedirectUris");

            migrationBuilder.RenameColumn(
                name: "AllowedOrigin",
                schema: "auth",
                table: "ClientApplication",
                newName: "AllowedOrigins");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ClientApplication_AllowedOrigins_IsJsonArray",
                schema: "auth",
                table: "ClientApplication",
                sql: "ISJSON([AllowedOrigins]) = 1 AND LEFT(LTRIM([AllowedOrigins]), 1) = N'['");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ClientApplication_PostLogoutRedirectUris_IsJsonArray",
                schema: "auth",
                table: "ClientApplication",
                sql: "ISJSON([PostLogoutRedirectUris]) = 1 AND LEFT(LTRIM([PostLogoutRedirectUris]), 1) = N'['");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ClientApplication_RedirectUris_IsJsonArray",
                schema: "auth",
                table: "ClientApplication",
                sql: "ISJSON([RedirectUris]) = 1 AND LEFT(LTRIM([RedirectUris]), 1) = N'['");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_ClientApplication_AllowedOrigins_IsJsonArray",
                schema: "auth",
                table: "ClientApplication");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ClientApplication_PostLogoutRedirectUris_IsJsonArray",
                schema: "auth",
                table: "ClientApplication");

            migrationBuilder.DropCheckConstraint(
                name: "CK_ClientApplication_RedirectUris_IsJsonArray",
                schema: "auth",
                table: "ClientApplication");

            migrationBuilder.RenameColumn(
                name: "RedirectUris",
                schema: "auth",
                table: "ClientApplication",
                newName: "RedirectUri");

            migrationBuilder.RenameColumn(
                name: "PostLogoutRedirectUris",
                schema: "auth",
                table: "ClientApplication",
                newName: "PostLogoutRedirectUri");

            migrationBuilder.RenameColumn(
                name: "AllowedOrigins",
                schema: "auth",
                table: "ClientApplication",
                newName: "AllowedOrigin");

            // Every application required PKCE before this migration, so true restores the old value.
            migrationBuilder.AddColumn<bool>(
                name: "RequirePkce",
                schema: "auth",
                table: "ClientApplication",
                type: "bit",
                nullable: false,
                defaultValue: true)
                .Annotation("Relational:DefaultConstraintName", "DF_ClientApplication_RequirePkce");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ClientApplication_AllowedOrigin_IsJson",
                schema: "auth",
                table: "ClientApplication",
                sql: "ISJSON([AllowedOrigin]) = 1");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ClientApplication_PostLogoutRedirectUri_IsJson",
                schema: "auth",
                table: "ClientApplication",
                sql: "ISJSON([PostLogoutRedirectUri]) = 1");

            migrationBuilder.AddCheckConstraint(
                name: "CK_ClientApplication_RedirectUri_IsJson",
                schema: "auth",
                table: "ClientApplication",
                sql: "ISJSON([RedirectUri]) = 1");
        }
    }
}
