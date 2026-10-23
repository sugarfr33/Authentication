using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class MfaRecoveryCodeConfiguration : IEntityTypeConfiguration<MfaRecoveryCode>
{
    public void Configure(EntityTypeBuilder<MfaRecoveryCode> builder)
    {
        builder.ToTable(nameof(MfaRecoveryCode), AuthDbContext.Schema);

        builder.HasKey(c => c.Id).HasName("PK_MfaRecoveryCode");

        builder.Property(c => c.CodeHash).HasMaxLength(32).IsFixedLength();

        builder.HasOne(c => c.User)
            .WithMany()
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_MfaRecoveryCode_User_UserId");

        builder.HasIndex(c => c.UserId).HasDatabaseName("IX_MfaRecoveryCode_UserId");
    }
}
