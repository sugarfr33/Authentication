using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    private static readonly string AllowedRevokedReasons = string.Join(
        ", ",
        new[]
        {
            RefreshTokenRevokedReason.Rotated,
            RefreshTokenRevokedReason.Reuse,
            RefreshTokenRevokedReason.Logout,
            RefreshTokenRevokedReason.LogoutAll,
            RefreshTokenRevokedReason.PasswordChange,
            RefreshTokenRevokedReason.Admin,
        }.Select(r => "N'" + r + "'"));

    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable(nameof(RefreshToken), AuthDbContext.Schema, t =>
        {
            t.HasCheckConstraint("CK_RefreshToken_Expiry", "[ExpiresUtc] > [CreatedUtc]");
            t.HasCheckConstraint(
                "CK_RefreshToken_RevokedReason",
                "[RevokedReason] IS NULL OR [RevokedReason] IN (" + AllowedRevokedReasons + ")");
        });

        builder.HasKey(t => t.Id).HasName("PK_RefreshToken");

        builder.Property(t => t.TokenHash).HasMaxLength(32).IsFixedLength();
        builder.Property(t => t.RevokedReason).HasMaxLength(32);
        builder.Property(t => t.IpAddress).HasMaxLength(45);
        builder.Property(t => t.UserAgent).HasMaxLength(512);
        builder.Property(t => t.RowVersion).IsRowVersion();

        builder.HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_RefreshToken_User_UserId");

        builder.HasOne(t => t.ClientApplication)
            .WithMany()
            .HasForeignKey(t => t.ClientApplicationId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_RefreshToken_ClientApplication_ClientApplicationId");

        builder.HasOne(t => t.ReplacedByToken)
            .WithMany()
            .HasForeignKey(t => t.ReplacedByTokenId)
            .OnDelete(DeleteBehavior.NoAction)
            .HasConstraintName("FK_RefreshToken_RefreshToken_ReplacedByTokenId");

        builder.HasIndex(t => t.TokenHash).IsUnique().HasDatabaseName("UQ_RefreshToken_TokenHash");
        builder.HasIndex(t => t.FamilyId).HasDatabaseName("IX_RefreshToken_FamilyId");
        builder.HasIndex(t => new { t.UserId, t.RevokedUtc }).HasDatabaseName("IX_RefreshToken_UserId_RevokedUtc");

        // FK support indexes (not in the plan list): without them, deleting an application or purging expired tokens
        // scans this table for referencing rows.
        builder.HasIndex(t => t.ClientApplicationId).HasDatabaseName("IX_RefreshToken_ClientApplicationId");
        builder.HasIndex(t => t.ReplacedByTokenId).HasDatabaseName("IX_RefreshToken_ReplacedByTokenId");
    }
}
