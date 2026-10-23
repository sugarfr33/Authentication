using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        builder.ToTable(nameof(Role), AuthDbContext.Schema);

        builder.HasKey(r => r.Id).HasName("PK_Role");

        builder.Property(r => r.Name).HasMaxLength(64);
        builder.Property(r => r.NormalizedName).HasMaxLength(64);
        builder.Property(r => r.Description).HasMaxLength(256);

        builder.HasOne(r => r.ClientApplication)
            .WithMany()
            .HasForeignKey(r => r.ClientApplicationId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("FK_Role_ClientApplication_ClientApplicationId");

        // No filter: SQL Server treats NULLs as equal here, so global role names (ClientApplicationId NULL) stay unique too.
        builder.HasIndex(r => new { r.ClientApplicationId, r.NormalizedName })
            .IsUnique()
            .HasFilter(null)
            .HasDatabaseName("UQ_Role_ClientApplicationId_NormalizedName");
        builder.HasIndex(r => r.ClientApplicationId).HasDatabaseName("IX_Role_ClientApplicationId");
    }
}
