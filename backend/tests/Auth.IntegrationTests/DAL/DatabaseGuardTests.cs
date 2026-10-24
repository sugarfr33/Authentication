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
}
