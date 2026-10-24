using Auth.DAL;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;

namespace Auth.UnitTests.DAL;

/// <summary>
/// T05 naming rule: every entity maps its table with an explicit ToTable, and no table name is plural (ends in "s"),
/// except the exempt word "Status". Checked on the convention model, where the configuration source of the table name is
/// still known.
/// </summary>
public class SingularNamingTests
{
    private static readonly string[] ExemptNames = ["Status"];

    [Fact]
    public void Every_entity_has_an_explicit_singular_table_in_the_auth_schema()
    {
        IConventionModel model = BuildAuthModel();

        Assert.Equal(12, model.GetEntityTypes().Count());
        Assert.Empty(FindViolations(model));
    }

    [Fact]
    public void Convention_model_has_the_same_entities_as_the_context()
    {
        using AuthDbContext context = new(new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer("Server=unused;Database=unused").Options);
        IEnumerable<string> fromContext = context.GetService<IDesignTimeModel>().Model.GetEntityTypes().Select(e => e.ClrType.Name);

        Assert.Equal(
            fromContext.Order(StringComparer.Ordinal),
            BuildAuthModel().GetEntityTypes().Select(e => e.ClrType.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Checker_flags_a_plural_table_and_an_entity_without_explicit_ToTable()
    {
        ModelBuilder builder = new(SqlServerConventionSetBuilder.Build());
        builder.Entity<PluralProbe>().ToTable("Widgets", "auth");
        builder.Entity<ImplicitProbe>();

        List<string> violations = FindViolations((IConventionModel)builder.Model);

        Assert.Contains("PluralProbe: table 'Widgets' ends in 's'", violations);
        Assert.Contains("ImplicitProbe: table name not set with an explicit ToTable", violations);
        Assert.Contains("ImplicitProbe: schema 'auth' not set explicitly", violations);
    }

    /// <summary>The DAL's configurations applied on SQL Server conventions, as AuthDbContext.OnModelCreating does.</summary>
    private static IConventionModel BuildAuthModel()
    {
        ModelBuilder builder = new(SqlServerConventionSetBuilder.Build());
        builder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);
        return (IConventionModel)builder.Model;
    }

    private static List<string> FindViolations(IConventionModel model)
    {
        List<string> violations = [];
        foreach (IConventionEntityType entity in model.GetEntityTypes())
        {
            string name = entity.ClrType.Name;
            string? table = entity.GetTableName();

            if (entity.GetTableNameConfigurationSource() != ConfigurationSource.Explicit)
            {
                violations.Add(name + ": table name not set with an explicit ToTable");
            }

            if (entity.GetSchemaConfigurationSource() != ConfigurationSource.Explicit || entity.GetSchema() != AuthDbContext.Schema)
            {
                violations.Add(name + ": schema '" + AuthDbContext.Schema + "' not set explicitly");
            }

            if (table is not null && table.EndsWith('s') && !ExemptNames.Contains(table, StringComparer.Ordinal))
            {
                violations.Add(name + ": table '" + table + "' ends in 's'");
            }
        }

        return violations;
    }

    private sealed class PluralProbe
    {
        public int Id { get; set; }
    }

    private sealed class ImplicitProbe
    {
        public int Id { get; set; }
    }
}
