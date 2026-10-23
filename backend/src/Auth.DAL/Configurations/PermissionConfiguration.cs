using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class PermissionConfiguration : IEntityTypeConfiguration<Permission>
{
    public void Configure(EntityTypeBuilder<Permission> builder)
    {
        builder.ToTable(nameof(Permission), AuthDbContext.Schema);

        builder.HasKey(p => p.Id).HasName("PK_Permission");

        builder.Property(p => p.Code).HasMaxLength(128);
        builder.Property(p => p.Description).HasMaxLength(256);

        builder.HasIndex(p => p.Code).IsUnique().HasDatabaseName("UQ_Permission_Code");
    }
}
