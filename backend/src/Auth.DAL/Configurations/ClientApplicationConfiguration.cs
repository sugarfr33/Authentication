using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class ClientApplicationConfiguration : IEntityTypeConfiguration<ClientApplication>
{
    public void Configure(EntityTypeBuilder<ClientApplication> builder)
    {
        builder.ToTable(nameof(ClientApplication), AuthDbContext.Schema, t =>
        {
            t.HasCheckConstraint("CK_ClientApplication_AllowedOrigin_IsJson", "ISJSON([AllowedOrigin]) = 1");
            t.HasCheckConstraint("CK_ClientApplication_RedirectUri_IsJson", "ISJSON([RedirectUri]) = 1");
            t.HasCheckConstraint("CK_ClientApplication_PostLogoutRedirectUri_IsJson", "ISJSON([PostLogoutRedirectUri]) = 1");
        });

        builder.HasKey(c => c.Id).HasName("PK_ClientApplication");

        builder.Property(c => c.ClientId).HasMaxLength(100);
        builder.Property(c => c.Name).HasMaxLength(128);
        builder.Property(c => c.Audience).HasMaxLength(256);
        builder.Property(c => c.AllowedOrigin).HasColumnType("nvarchar(max)");
        builder.Property(c => c.RedirectUri).HasColumnType("nvarchar(max)");
        builder.Property(c => c.PostLogoutRedirectUri).HasColumnType("nvarchar(max)");

        // The database default covers raw inserts; EF always sends the value so an explicit false is never replaced by the default.
        builder.Property(c => c.RequirePkce)
            .HasDefaultValue(true, "DF_ClientApplication_RequirePkce")
            .ValueGeneratedNever();

        builder.HasIndex(c => c.ClientId).IsUnique().HasDatabaseName("UQ_ClientApplication_ClientId");

        // T18: one audience per application, so tokens of two applications are never interchangeable.
        builder.HasIndex(c => c.Audience).IsUnique().HasDatabaseName("UQ_ClientApplication_Audience");
    }
}
