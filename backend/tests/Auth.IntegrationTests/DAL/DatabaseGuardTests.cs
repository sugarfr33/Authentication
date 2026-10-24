namespace Auth.IntegrationTests.DAL;

/// <summary>The fixture must never create or drop a database that is not a throwaway *_Test one. No database needed.</summary>
public class DatabaseGuardTests
{
    [Theory]
    [InlineData(@"Server=.\SQLEXPRESS;Database=CentralAuth;Trusted_Connection=True;")]
    [InlineData(@"Server=.\SQLEXPRESS;Initial Catalog=CentralAuth;Trusted_Connection=True;")]
    [InlineData(@"Server=.\SQLEXPRESS;Database=CentralAuth_Testing;Trusted_Connection=True;")]
    [InlineData(@"Server=.\SQLEXPRESS;Database=CentralAuth_test;Trusted_Connection=True;")]
    [InlineData(@"Server=.\SQLEXPRESS;Trusted_Connection=True;")]
    public void Guard_refuses_non_test_databases(string connectionString)
    {
        Assert.Throws<InvalidOperationException>(() => SqlServerDatabaseFixture.EnsureThrowawayDatabase(connectionString));
    }

    [Theory]
    [InlineData(@"Server=.\SQLEXPRESS;Database=CentralAuth_Test;Trusted_Connection=True;")]
    [InlineData(@"Server=.\SQLEXPRESS;Initial Catalog=Anything_Test;Trusted_Connection=True;")]
    public void Guard_allows_test_databases(string connectionString)
    {
        SqlServerDatabaseFixture.EnsureThrowawayDatabase(connectionString);
    }

    /// <summary>Parallel runs get their own databases: every fixture name is unique to the run and still ends with _Test.</summary>
    [Theory]
    [InlineData("CentralAuth")]
    [InlineData("CentralAuth_Test")]
    [InlineData("CentralAuth_Api")]
    [InlineData("CentralAuth_Migrations")]
    public void Unique_names_carry_the_run_id_and_pass_the_guard(string baseName)
    {
        string name = TestDatabaseNames.Unique(baseName);

        Assert.Matches("^CentralAuth[A-Za-z_]*_run[0-9a-f]{8}_Test$", name);
        Assert.Contains(TestDatabaseNames.RunId, name, StringComparison.Ordinal);
        SqlServerDatabaseFixture.EnsureThrowawayDatabase(@"Server=.\SQLEXPRESS;Database=" + name + ";");
    }

    [Fact]
    public void The_shared_fixture_and_the_api_fixture_use_this_runs_names()
    {
        string shared = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(new SqlServerDatabaseFixture().ConnectionString).InitialCatalog;

        Assert.EndsWith("_run" + TestDatabaseNames.RunId + "_Test", shared, StringComparison.Ordinal);
        Assert.NotEqual("CentralAuth_Test", shared);
    }
}
