using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.DAL.Migrations
{
    /// <inheritdoc />
    internal partial class RetentionAndAudienceIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_ExpiresUtc",
                schema: "auth",
                table: "RefreshToken",
                column: "ExpiresUtc");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetToken_ExpiresUtc",
                schema: "auth",
                table: "PasswordResetToken",
                column: "ExpiresUtc");

            migrationBuilder.CreateIndex(
                name: "IX_EmailVerificationToken_ExpiresUtc",
                schema: "auth",
                table: "EmailVerificationToken",
                column: "ExpiresUtc");

            // Refuse, instead of guessing, when existing rows already share an audience: an operator must give each
            // application its own audience first (docs/client-applications.md). Only bootstrap data exists so far.
            migrationBuilder.Sql(
                "IF EXISTS (SELECT [Audience] FROM [auth].[ClientApplication] GROUP BY [Audience] HAVING COUNT(*) > 1) "
                + "THROW 50018, 'ClientApplication rows share an Audience; give each application its own audience before applying RetentionAndAudienceIndexes (see docs/client-applications.md).', 1;");

            migrationBuilder.CreateIndex(
                name: "UQ_ClientApplication_Audience",
                schema: "auth",
                table: "ClientApplication",
                column: "Audience",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshToken_ExpiresUtc",
                schema: "auth",
                table: "RefreshToken");

            migrationBuilder.DropIndex(
                name: "IX_PasswordResetToken_ExpiresUtc",
                schema: "auth",
                table: "PasswordResetToken");

            migrationBuilder.DropIndex(
                name: "IX_EmailVerificationToken_ExpiresUtc",
                schema: "auth",
                table: "EmailVerificationToken");

            migrationBuilder.DropIndex(
                name: "UQ_ClientApplication_Audience",
                schema: "auth",
                table: "ClientApplication");
        }
    }
}
