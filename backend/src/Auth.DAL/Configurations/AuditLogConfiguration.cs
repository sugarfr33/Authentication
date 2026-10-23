using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable(nameof(AuditLog), AuthDbContext.Schema);

        // bigint identity: the table is append-heavy.
        builder.HasKey(a => a.Id).HasName("PK_AuditLog");
        builder.Property(a => a.Id).UseIdentityColumn();

        builder.Property(a => a.EventType).HasMaxLength(64);
        builder.Property(a => a.IpAddress).HasMaxLength(45);
        builder.Property(a => a.UserAgent).HasMaxLength(512);
        builder.Property(a => a.Detail).HasMaxLength(2000);
        builder.Property(a => a.CorrelationId).HasMaxLength(64);

        // Audit rows outlive the user or application they mention.
        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.SetNull)
            .HasConstraintName("FK_AuditLog_User_UserId");

        builder.HasOne<ClientApplication>()
            .WithMany()
            .HasForeignKey(a => a.ClientApplicationId)
            .OnDelete(DeleteBehavior.SetNull)
            .HasConstraintName("FK_AuditLog_ClientApplication_ClientApplicationId");

        builder.HasIndex(a => new { a.UserId, a.OccurredUtc }).HasDatabaseName("IX_AuditLog_UserId_OccurredUtc");
        builder.HasIndex(a => new { a.EventType, a.OccurredUtc }).HasDatabaseName("IX_AuditLog_EventType_OccurredUtc");

        // FK support index (not in the plan list) so deleting an application does not scan the audit table.
        builder.HasIndex(a => a.ClientApplicationId).HasDatabaseName("IX_AuditLog_ClientApplicationId");
    }
}
