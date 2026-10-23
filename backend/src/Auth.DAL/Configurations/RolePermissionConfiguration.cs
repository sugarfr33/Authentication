using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    public void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        builder.ToTable(nameof(RolePermission), AuthDbContext.Schema);

        builder.HasKey(rp => new { rp.RoleId, rp.PermissionId }).HasName("PK_RolePermission");

        builder.HasOne(rp => rp.Role)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.RoleId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_RolePermission_Role_RoleId");

        builder.HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_RolePermission_Permission_PermissionId");

        builder.HasIndex(rp => rp.PermissionId).HasDatabaseName("IX_RolePermission_PermissionId");
    }
}
