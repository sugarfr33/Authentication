using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Auth.IntegrationTests.DAL;

/// <summary>
/// Throwaway database names that are unique per test run (process), so parallel runs on one SQL Server never share
/// or drop each other's databases. Every name still ends with <c>_Test</c>, which the fixture guard requires.
/// </summary>
public static partial class TestDatabaseNames
{
    /// <summary>Marker between the base name and the run id; also how leftovers of crashed runs are recognised.</summary>
    public const string RunMarker = "_run";

    /// <summary>8 random hex characters, fixed for the whole test process.</summary>
    public static readonly string RunId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));

    /// <summary>For example <c>CentralAuth_Api</c> becomes <c>CentralAuth_Api_run1a2b3c4d_Test</c>.</summary>
    public static string Unique(string baseName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseName);
        string root = baseName.EndsWith(SqlServerDatabaseFixture.ThrowawaySuffix, StringComparison.Ordinal)
            ? baseName[..^SqlServerDatabaseFixture.ThrowawaySuffix.Length]
            : baseName;
        return root + RunMarker + RunId + SqlServerDatabaseFixture.ThrowawaySuffix;
    }

    /// <summary>The same server and credentials with this run's unique database name.</summary>
    public static string WithUniqueDatabase(string connectionString, string baseName) =>
        new SqlConnectionStringBuilder(connectionString) { InitialCatalog = Unique(baseName) }.ConnectionString;

    /// <summary>
    /// True only for names this class creates: <c>CentralAuth</c>, an optional <c>_Word</c>, the run marker, exactly 8
    /// lowercase hex digits and <c>_Test</c>. Anything else is never dropped.
    /// </summary>
    public static bool IsRunDatabase(string name) => RunDatabaseName().IsMatch(name);

    /// <summary>
    /// Drops databases left behind by crashed runs: only names <see cref="IsRunDatabase"/> accepts that are older than
    /// <paramref name="olderThan"/> (so a parallel run in progress is never touched).
    /// </summary>
    public static async Task DropStaleAsync(string connectionString, TimeSpan olderThan)
    {
        SqlConnectionStringBuilder master = new(connectionString) { InitialCatalog = "master" };
        await using SqlConnection connection = new(master.ConnectionString);
        await connection.OpenAsync();

        List<string> stale = [];
        await using (SqlCommand find = connection.CreateCommand())
        {
            find.CommandText =
                "SELECT name FROM sys.databases WHERE name LIKE 'CentralAuth%[_]run[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][_]Test' "
                + "AND create_date < DATEADD(SECOND, -@age, GETDATE())";
            find.Parameters.AddWithValue("@age", (int)olderThan.TotalSeconds);
            await using SqlDataReader reader = await find.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                stale.Add(reader.GetString(0));
            }
        }

        foreach (string name in stale)
        {
            SqlServerDatabaseFixture.EnsureThrowawayDatabase(new SqlConnectionStringBuilder(connectionString) { InitialCatalog = name }.ConnectionString);
            if (!IsRunDatabase(name))
            {
                continue;
            }

            await using SqlCommand drop = connection.CreateCommand();
            drop.CommandText = "ALTER DATABASE " + QuoteName(name) + " SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE " + QuoteName(name) + ";";
            await drop.ExecuteNonQueryAsync();
        }
    }

    [GeneratedRegex("^CentralAuth(_[A-Za-z]+)?_run[0-9a-f]{8}_Test$", RegexOptions.CultureInvariant)]
    private static partial Regex RunDatabaseName();

    private static string QuoteName(string name) => "[" + name.Replace("]", "]]", StringComparison.Ordinal) + "]";
}
