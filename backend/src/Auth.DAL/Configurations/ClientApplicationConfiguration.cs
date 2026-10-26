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
            // T29: each list is a JSON array (portable check: valid JSON that starts with "[", SQL Server 2019 and later).
            t.HasCheckConstraint("CK_ClientApplication_AllowedOrigins_IsJsonArray", JsonArray("AllowedOrigins"));
            t.HasCheckConstraint("CK_ClientApplication_RedirectUris_IsJsonArray", JsonArray("RedirectUris"));
            t.HasCheckConstraint("CK_ClientApplication_PostLogoutRedirectUris_IsJsonArray", JsonArray("PostLogoutRedirectUris"));
        });

        builder.HasKey(c => c.Id).HasName("PK_ClientApplication");

        builder.Property(c => c.ClientId).HasMaxLength(100);
        builder.Property(c => c.Name).HasMaxLength(128);
        builder.Property(c => c.Audience).HasMaxLength(256);
        builder.Property(c => c.AllowedOrigins).HasColumnType("nvarchar(max)");
        builder.Property(c => c.RedirectUris).HasColumnType("nvarchar(max)");
        builder.Property(c => c.PostLogoutRedirectUris).HasColumnType("nvarchar(max)");

        builder.HasIndex(c => c.ClientId).IsUnique().HasDatabaseName("UQ_ClientApplication_ClientId");

        // T18: one audience per application, so tokens of two applications are never interchangeable.
        builder.HasIndex(c => c.Audience).IsUnique().HasDatabaseName("UQ_ClientApplication_Audience");
    }

    /// <summary>The CHECK expression for a JSON array column. Also used by the T29 migration.</summary>
    internal static string JsonArray(string column) => "ISJSON([" + column + "]) = 1 AND LEFT(LTRIM([" + column + "]), 1) = N'['";
}
