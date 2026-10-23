using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class EmailVerificationTokenConfiguration : IEntityTypeConfiguration<EmailVerificationToken>
{
    public void Configure(EntityTypeBuilder<EmailVerificationToken> builder)
    {
        builder.ToTable(nameof(EmailVerificationToken), AuthDbContext.Schema);

        builder.HasKey(t => t.Id).HasName("PK_EmailVerificationToken");

        builder.Property(t => t.TokenHash).HasMaxLength(32).IsFixedLength();

        builder.HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_EmailVerificationToken_User_UserId");

        builder.HasIndex(t => t.TokenHash).IsUnique().HasDatabaseName("UQ_EmailVerificationToken_TokenHash");
        builder.HasIndex(t => t.UserId).HasDatabaseName("IX_EmailVerificationToken_UserId");
    }
}
