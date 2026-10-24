using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Auth.DAL;

/// <summary>
/// Lets <c>dotnet ef</c> build the context without the API host. The connection string comes from the
/// <see cref="ConnectionStringVariable"/> environment variable, or else the local SQLEXPRESS dev database.
/// </summary>
internal sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public const string ConnectionStringVariable = "CENTRALAUTH_CONNECTION";

    public const string LocalConnectionString =
        @"Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;TrustServerCertificate=True;";

    public AuthDbContext CreateDbContext(string[] args)
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable(ConnectionStringVariable);
        string connectionString = string.IsNullOrWhiteSpace(fromEnvironment) ? LocalConnectionString : fromEnvironment;

        DbContextOptionsBuilder<AuthDbContext> builder = new();
        AuthDbContext.UseAuthSqlServer(builder, connectionString);

        return new AuthDbContext(builder.Options);
    }
}
