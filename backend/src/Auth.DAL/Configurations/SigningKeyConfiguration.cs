using Auth.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.DAL.Configurations;

internal sealed class SigningKeyConfiguration : IEntityTypeConfiguration<SigningKey>
{
    private static readonly string AllowedStatuses = SqlList(
        SigningKeyStatus.Active, SigningKeyStatus.Retiring, SigningKeyStatus.Retired);

    private static readonly string AllowedAlgorithms = SqlList(SigningKeyAlgorithm.RS256, SigningKeyAlgorithm.ES256);

    public void Configure(EntityTypeBuilder<SigningKey> builder)
    {
        builder.ToTable(nameof(SigningKey), AuthDbContext.Schema, t =>
        {
            t.HasCheckConstraint("CK_SigningKey_Status", "[Status] IN (" + AllowedStatuses + ")");
            t.HasCheckConstraint("CK_SigningKey_Algorithm", "[Algorithm] IN (" + AllowedAlgorithms + ")");
        });

        builder.HasKey(k => k.Id).HasName("PK_SigningKey");

        builder.Property(k => k.Kid).HasMaxLength(64);
        builder.Property(k => k.Algorithm).HasMaxLength(10);
        builder.Property(k => k.PublicKeyJwk).HasColumnType("nvarchar(max)");
        builder.Property(k => k.PrivateKeyReference).HasMaxLength(256);
        builder.Property(k => k.Status).HasMaxLength(16);

        builder.HasIndex(k => k.Kid).IsUnique().HasDatabaseName("UQ_SigningKey_Kid");
        builder.HasIndex(k => k.Status).HasDatabaseName("IX_SigningKey_Status");
    }

    private static string SqlList(params string[] values) => string.Join(", ", values.Select(v => "N'" + v + "'"));
}
