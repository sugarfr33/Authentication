using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
{
    public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
    {
        builder.ToTable(nameof(AuthorizationCode), AuthDbContext.Schema, t =>
        {
            t.HasCheckConstraint("CK_AuthorizationCode_Expiry", "[ExpiresUtc] > [CreatedUtc]");
            t.HasCheckConstraint("CK_AuthorizationCode_CodeChallenge_Length", "LEN([CodeChallenge]) BETWEEN 43 AND 128");
        });

        builder.HasKey(c => c.Id).HasName("PK_AuthorizationCode");

        builder.Property(c => c.CodeHash).HasMaxLength(32).IsFixedLength();
        builder.Property(c => c.RedirectUri).HasMaxLength(512);
        builder.Property(c => c.CodeChallenge).HasMaxLength(128).IsUnicode(false);

        builder.HasOne(c => c.User)
            .WithMany()
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_AuthorizationCode_User_UserId");

        builder.HasOne(c => c.ClientApplication)
            .WithMany()
            .HasForeignKey(c => c.ClientApplicationId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_AuthorizationCode_ClientApplication_ClientApplicationId");

        builder.HasIndex(c => c.CodeHash).IsUnique().HasDatabaseName("UQ_AuthorizationCode_CodeHash");
        builder.HasIndex(c => c.ExpiresUtc).HasDatabaseName("IX_AuthorizationCode_ExpiresUtc");
    }
}
