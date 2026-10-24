using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.DAL.Migrations
{
    /// <inheritdoc />
    internal partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "auth");

            migrationBuilder.CreateTable(
                name: "ClientApplication",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Audience = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    AllowedOrigin = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RedirectUri = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PostLogoutRedirectUri = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequirePkce = table.Column<bool>(type: "bit", nullable: false, defaultValue: true)
                        .Annotation("Relational:DefaultConstraintName", "DF_ClientApplication_RequirePkce"),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    UpdatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientApplication", x => x.Id);
                    table.CheckConstraint("CK_ClientApplication_AllowedOrigin_IsJson", "ISJSON([AllowedOrigin]) = 1");
                    table.CheckConstraint("CK_ClientApplication_PostLogoutRedirectUri_IsJson", "ISJSON([PostLogoutRedirectUri]) = 1");
                    table.CheckConstraint("CK_ClientApplication_RedirectUri_IsJson", "ISJSON([RedirectUri]) = 1");
                });

            migrationBuilder.CreateTable(
                name: "Permission",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Code = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Permission", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SigningKey",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kid = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Algorithm = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: false),
                    PublicKeyJwk = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PrivateKeyReference = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    ActivatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true),
                    RetireAfterUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKey", x => x.Id);
                    table.CheckConstraint("CK_SigningKey_Algorithm", "[Algorithm] IN (N'RS256', N'ES256')");
                    table.CheckConstraint("CK_SigningKey_Status", "[Status] IN (N'Active', N'Retiring', N'Retired')");
                });

            migrationBuilder.CreateTable(
                name: "User",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    NormalizedEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    EmailVerified = table.Column<bool>(type: "bit", nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    FailedLoginCount = table.Column<int>(type: "int", nullable: false),
                    LockoutEndUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true),
                    LockoutLevel = table.Column<int>(type: "int", nullable: false),
                    MfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    MfaSecretEncrypted = table.Column<byte[]>(type: "varbinary(256)", maxLength: 256, nullable: true),
                    SecurityStamp = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false, defaultValueSql: "sysutcdatetime()")
                        .Annotation("Relational:DefaultConstraintName", "DF_User_CreatedUtc"),
                    UpdatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    LastLoginUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_User", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Role",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientApplicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Name = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    NormalizedName = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    IsSystem = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Role", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Role_ClientApplication_ClientApplicationId",
                        column: x => x.ClientApplicationId,
                        principalSchema: "auth",
                        principalTable: "ClientApplication",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AuditLog",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    OccurredUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    EventType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ClientApplicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    IpAddress = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    Detail = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: true),
                    CorrelationId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLog", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuditLog_ClientApplication_ClientApplicationId",
                        column: x => x.ClientApplicationId,
                        principalSchema: "auth",
                        principalTable: "ClientApplication",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_AuditLog_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "EmailVerificationToken",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenHash = table.Column<byte[]>(type: "binary(32)", fixedLength: true, maxLength: 32, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    UsedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailVerificationToken", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EmailVerificationToken_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaRecoveryCode",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CodeHash = table.Column<byte[]>(type: "binary(32)", fixedLength: true, maxLength: 32, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    UsedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaRecoveryCode", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaRecoveryCode_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PasswordResetToken",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenHash = table.Column<byte[]>(type: "binary(32)", fixedLength: true, maxLength: 32, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    UsedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true),
                    RequestIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordResetToken", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasswordResetToken_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RefreshToken",
                schema: "auth",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientApplicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    FamilyId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenHash = table.Column<byte[]>(type: "binary(32)", fixedLength: true, maxLength: 32, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false),
                    RevokedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: true),
                    RevokedReason = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    ReplacedByTokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    IpAddress = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    UserAgent = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshToken", x => x.Id);
                    table.CheckConstraint("CK_RefreshToken_Expiry", "[ExpiresUtc] > [CreatedUtc]");
                    table.CheckConstraint("CK_RefreshToken_RevokedReason", "[RevokedReason] IS NULL OR [RevokedReason] IN (N'Rotated', N'Reuse', N'Logout', N'LogoutAll', N'PasswordChange', N'Admin')");
                    table.ForeignKey(
                        name: "FK_RefreshToken_ClientApplication_ClientApplicationId",
                        column: x => x.ClientApplicationId,
                        principalSchema: "auth",
                        principalTable: "ClientApplication",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RefreshToken_RefreshToken_ReplacedByTokenId",
                        column: x => x.ReplacedByTokenId,
                        principalSchema: "auth",
                        principalTable: "RefreshToken",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_RefreshToken_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RolePermission",
                schema: "auth",
                columns: table => new
                {
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PermissionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RolePermission", x => new { x.RoleId, x.PermissionId });
                    table.ForeignKey(
                        name: "FK_RolePermission_Permission_PermissionId",
                        column: x => x.PermissionId,
                        principalSchema: "auth",
                        principalTable: "Permission",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RolePermission_Role_RoleId",
                        column: x => x.RoleId,
                        principalSchema: "auth",
                        principalTable: "Role",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserRole",
                schema: "auth",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AssignedUtc = table.Column<DateTime>(type: "datetime2(7)", precision: 7, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRole", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_UserRole_Role_RoleId",
                        column: x => x.RoleId,
                        principalSchema: "auth",
                        principalTable: "Role",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRole_User_UserId",
                        column: x => x.UserId,
                        principalSchema: "auth",
                        principalTable: "User",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_ClientApplicationId",
                schema: "auth",
                table: "AuditLog",
                column: "ClientApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_EventType_OccurredUtc",
                schema: "auth",
                table: "AuditLog",
                columns: new[] { "EventType", "OccurredUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_UserId_OccurredUtc",
                schema: "auth",
                table: "AuditLog",
                columns: new[] { "UserId", "OccurredUtc" });

            migrationBuilder.CreateIndex(
                name: "UQ_ClientApplication_ClientId",
                schema: "auth",
                table: "ClientApplication",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EmailVerificationToken_UserId",
                schema: "auth",
                table: "EmailVerificationToken",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "UQ_EmailVerificationToken_TokenHash",
                schema: "auth",
                table: "EmailVerificationToken",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCode_UserId",
                schema: "auth",
                table: "MfaRecoveryCode",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetToken_UserId",
                schema: "auth",
                table: "PasswordResetToken",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "UQ_PasswordResetToken_TokenHash",
                schema: "auth",
                table: "PasswordResetToken",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_Permission_Code",
                schema: "auth",
                table: "Permission",
                column: "Code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_ClientApplicationId",
                schema: "auth",
                table: "RefreshToken",
                column: "ClientApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_FamilyId",
                schema: "auth",
                table: "RefreshToken",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_ReplacedByTokenId",
                schema: "auth",
                table: "RefreshToken",
                column: "ReplacedByTokenId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_UserId_RevokedUtc",
                schema: "auth",
                table: "RefreshToken",
                columns: new[] { "UserId", "RevokedUtc" });

            migrationBuilder.CreateIndex(
                name: "UQ_RefreshToken_TokenHash",
                schema: "auth",
                table: "RefreshToken",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Role_ClientApplicationId",
                schema: "auth",
                table: "Role",
                column: "ClientApplicationId");

            migrationBuilder.CreateIndex(
                name: "UQ_Role_ClientApplicationId_NormalizedName",
                schema: "auth",
                table: "Role",
                columns: new[] { "ClientApplicationId", "NormalizedName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RolePermission_PermissionId",
                schema: "auth",
                table: "RolePermission",
                column: "PermissionId");

            migrationBuilder.CreateIndex(
                name: "IX_SigningKey_Status",
                schema: "auth",
                table: "SigningKey",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "UQ_SigningKey_Kid",
                schema: "auth",
                table: "SigningKey",
                column: "Kid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ_User_NormalizedEmail",
                schema: "auth",
                table: "User",
                column: "NormalizedEmail",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserRole_RoleId",
                schema: "auth",
                table: "UserRole",
                column: "RoleId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLog",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "EmailVerificationToken",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "MfaRecoveryCode",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "PasswordResetToken",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "RefreshToken",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "RolePermission",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "SigningKey",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "UserRole",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "Permission",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "Role",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "User",
                schema: "auth");

            migrationBuilder.DropTable(
                name: "ClientApplication",
                schema: "auth");
        }
    }
}
