using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.DAL.Migrations
{
    /// <inheritdoc />
    internal partial class EmailVerificationPendingRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PendingDisplayName",
                schema: "auth",
                table: "EmailVerificationToken",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PendingPasswordHash",
                schema: "auth",
                table: "EmailVerificationToken",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PendingDisplayName",
                schema: "auth",
                table: "EmailVerificationToken");

            migrationBuilder.DropColumn(
                name: "PendingPasswordHash",
                schema: "auth",
                table: "EmailVerificationToken");
        }
    }
}
