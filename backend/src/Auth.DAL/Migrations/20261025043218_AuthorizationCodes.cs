using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.DAL.Migrations
{
    /// <inheritdoc />
    internal partial class AuthorizationCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Any error aborts and rolls back the whole batch (also when the idempotent script runs outside EF).
            migrationBuilder.Sql("SET XACT_ABORT ON;");

            migrationBuilder.CreateTable(
                name: "AuthorizationCode",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CodeHash = table.Column<byte[]>(type: "binary(32)", fixedLength: true, maxLength: 32, nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientApplicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RedirectUri = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    CodeChallenge = table.Column<string>(type: "varchar(128)", unicode: false, maxLength: 128, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    UsedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true),
                    FamilyId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCode", x => x.Id);
                    table.CheckConstraint("CK_AuthorizationCode_CodeChallenge_Length", "LEN([CodeChallenge]) BETWEEN 43 AND 128");
                    table.CheckConstraint("CK_AuthorizationCode_Expiry", "[ExpiresUtc] > [CreatedUtc]");
                    table.ForeignKey(
                        name: "FK_AuthorizationCode_ClientApplication_ClientApplicationId",
                        column: x => x.ClientApplicationId,
                        principalSchema: "auth",
                        principalTable: "ClientApplication",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AuthorizationCode_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCode_ClientApplicationId",
                schema: "auth",
                table: "AuthorizationCode",
                column: "ClientApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCode_ExpiresUtc",
                schema: "auth",
                table: "AuthorizationCode",
                column: "ExpiresUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCode_UserId",
                schema: "auth",
                table: "AuthorizationCode",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "UQ_AuthorizationCode_CodeHash",
                schema: "auth",
                table: "AuthorizationCode",
                column: "CodeHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthorizationCode",
                schema: "auth");
        }
    }
}
