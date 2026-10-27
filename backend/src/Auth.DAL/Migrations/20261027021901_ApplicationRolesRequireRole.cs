using Auth.DAL.Configurations;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.DAL.Migrations
{
    /// <summary>
    /// T30 (schema change approved by the human): per-application access.
    /// <list type="bullet">
    /// <item>auth.ClientApplication.RequireRole bit NOT NULL, default 0 (DF_ClientApplication_RequireRole): existing
    /// applications keep today's behaviour (any signed-in user may sign in).</item>
    /// <item>CK_Role_GlobalName_NotApplicationPrefix: a global role (no application) may not be named app:..., the claim
    /// prefix of application roles. Rows that would break it stop the migration first with a clear message.</item>
    /// </list>
    /// </summary>
    internal partial class ApplicationRolesRequireRole : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Any error aborts and rolls back the whole batch (also when the idempotent script runs outside EF).
            migrationBuilder.Sql("SET XACT_ABORT ON;");

            migrationBuilder.Sql(
                "IF EXISTS (SELECT 1 FROM [auth].[Role] WHERE NOT (" + RoleConfiguration.GlobalNameNotApplicationPrefix + ")) "
                + "THROW 50030, 'A global role is named app:...; rename it before applying ApplicationRolesRequireRole (see docs/authorization.md).', 1;");

            migrationBuilder.AddColumn<bool>(
                name: "RequireRole",
                schema: "auth",
                table: "ClientApplication",
                type: "bit",
                nullable: false,
                defaultValue: false)
                .Annotation("Relational:DefaultConstraintName", "DF_ClientApplication_RequireRole");

            migrationBuilder.AddCheckConstraint(
                name: "CK_Role_GlobalName_NotApplicationPrefix",
                schema: "auth",
                table: "Role",
                sql: RoleConfiguration.GlobalNameNotApplicationPrefix);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_Role_GlobalName_NotApplicationPrefix",
                schema: "auth",
                table: "Role");

            migrationBuilder.DropColumn(
                name: "RequireRole",
                schema: "auth",
                table: "ClientApplication")
                .Annotation("Relational:DefaultConstraintName", "DF_ClientApplication_RequireRole");
        }
    }
}
