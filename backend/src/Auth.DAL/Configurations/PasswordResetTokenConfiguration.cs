using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class PasswordResetTokenConfiguration : IEntityTypeConfiguration<PasswordResetToken>
{
    public void Configure(EntityTypeBuilder<PasswordResetToken> builder)
    {
        builder.ToTable(nameof(PasswordResetToken), AuthDbContext.Schema);

        builder.HasKey(t => t.Id).HasName("PK_PasswordResetToken");

        builder.Property(t => t.TokenHash).HasMaxLength(32).IsFixedLength();
        builder.Property(t => t.RequestIp).HasMaxLength(45);

        builder.HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_PasswordResetToken_User_UserId");

        builder.HasIndex(t => t.TokenHash).IsUnique().HasDatabaseName("UQ_PasswordResetToken_TokenHash");
        builder.HasIndex(t => t.UserId).HasDatabaseName("IX_PasswordResetToken_UserId");
        builder.HasIndex(t => t.ExpiresUtc).HasDatabaseName("IX_PasswordResetToken_ExpiresUtc");
    }
}
