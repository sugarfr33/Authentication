using Auth.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.DAL;

/// <summary>
/// EF Core context for the <c>CentralAuth</c> database. Internal: Services only sees repositories (T04).
/// DbSet names are singular and equal the table names; every table is mapped explicitly in its configuration.
/// </summary>
internal sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public const string Schema = "auth";

    public const string MigrationsHistoryTable = "__EFMigrationsHistory";

    /// <summary>
    /// The one place the provider is configured, shared by DI and the design-time factory so they cannot drift.
    /// The migrations history table also lives in the auth schema.
    /// </summary>
    public static DbContextOptionsBuilder UseAuthSqlServer(DbContextOptionsBuilder options, string connectionString) =>
        options.UseSqlServer(connectionString, sql => sql.MigrationsHistoryTable(MigrationsHistoryTable, Schema));

    public DbSet<User> User => Set<User>();

    public DbSet<Role> Role => Set<Role>();

    public DbSet<UserRole> UserRole => Set<UserRole>();

    public DbSet<Permission> Permission => Set<Permission>();

    public DbSet<RolePermission> RolePermission => Set<RolePermission>();

    public DbSet<ClientApplication> ClientApplication => Set<ClientApplication>();

    public DbSet<RefreshToken> RefreshToken => Set<RefreshToken>();

    public DbSet<PasswordResetToken> PasswordResetToken => Set<PasswordResetToken>();

    public DbSet<EmailVerificationToken> EmailVerificationToken => Set<EmailVerificationToken>();

    public DbSet<AuditLog> AuditLog => Set<AuditLog>();

    public DbSet<SigningKey> SigningKey => Set<SigningKey>();

    public DbSet<MfaRecoveryCode> MfaRecoveryCode => Set<MfaRecoveryCode>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // All timestamps are UTC datetime2(7).
        configurationBuilder.Properties<DateTime>().HavePrecision(7);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);
    }
}
