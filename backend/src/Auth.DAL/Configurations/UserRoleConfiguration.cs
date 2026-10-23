using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> builder)
    {
        builder.ToTable(nameof(UserRole), AuthDbContext.Schema);

        builder.HasKey(ur => new { ur.UserId, ur.RoleId }).HasName("PK_UserRole");

        builder.HasOne(ur => ur.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_UserRole_User_UserId");

        builder.HasOne(ur => ur.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ur => ur.RoleId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("FK_UserRole_Role_RoleId");

        builder.HasIndex(ur => ur.RoleId).HasDatabaseName("IX_UserRole_RoleId");
    }
}
