using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable(nameof(User), AuthDbContext.Schema);

        builder.HasKey(u => u.Id).HasName("PK_User");

        builder.Property(u => u.Email).HasMaxLength(256);
        builder.Property(u => u.NormalizedEmail).HasMaxLength(256);
        builder.Property(u => u.PasswordHash).HasMaxLength(512);
        builder.Property(u => u.DisplayName).HasMaxLength(128);
        builder.Property(u => u.MfaSecretEncrypted).HasMaxLength(256);
        builder.Property(u => u.CreatedUtc).HasDefaultValueSql("sysutcdatetime()", "DF_User_CreatedUtc");
        builder.Property(u => u.RowVersion).IsRowVersion();

        builder.HasIndex(u => u.NormalizedEmail).IsUnique().HasDatabaseName("UQ_User_NormalizedEmail");
    }
}
