using System.Reflection;

namespace Auth.ArchitectureTests;

/// <summary>EF Core stays an implementation detail of Auth.DAL (T03): nothing public exposes an EF type.</summary>
public class DalSurfaceTests
{
    private const string EfNamespace = "Microsoft.EntityFrameworkCore";

    private static readonly Assembly Dal = typeof(Auth.DAL.AssemblyMarker).Assembly;

    [Fact]
    public void DbContext_and_entity_configurations_are_not_public()
    {
        IEnumerable<string> publicEfTypes = Dal.GetExportedTypes()
            .Where(t => BaseTypesAndInterfaces(t).Any(IsEfType))
            .Select(t => t.FullName ?? t.Name);

        Assert.Empty(publicEfTypes);
    }

    [Fact]
    public void DAL_contains_the_internal_DbContext_and_thirteen_configurations()
    {
        Type[] types = Dal.GetTypes();

        Assert.Contains(types, t => t.Name == "AuthDbContext" && !t.IsPublic && t.BaseType?.FullName == EfNamespace + ".DbContext");
        Assert.Equal(13, types.Count(t => !t.IsPublic && t.GetInterfaces().Any(i => i.Name == "IEntityTypeConfiguration`1")));
    }

    [Fact]
    public void Public_members_do_not_expose_EF_types()
    {
        IEnumerable<string> offenders = Dal.GetExportedTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(m => IsEfType(m.ReturnType) || m.GetParameters().Any(p => IsEfType(p.ParameterType)))
            .Select(m => m.DeclaringType?.Name + "." + m.Name);

        Assert.Empty(offenders);
    }

    [Fact]
    public void Public_DAL_types_are_only_interfaces_exceptions_and_static_classes()
    {
        IEnumerable<string> offenders = Dal.GetExportedTypes()
            .Where(t => !t.IsInterface && !typeof(Exception).IsAssignableFrom(t) && !(t.IsAbstract && t.IsSealed))
            .Select(t => t.FullName ?? t.Name);

        Assert.Empty(offenders);
    }

    /// <summary>T04: every query is LINQ or interpolated FromSql/ExecuteSql (parameterized); the raw-string APIs are banned.</summary>
    [Fact]
    public void DAL_source_uses_no_raw_SQL_APIs()
    {
        string[] banned = ["FromSqlRaw", "ExecuteSqlRaw", "SqlQueryRaw"];
        string dalSource = Path.Combine(RepoPaths.BackendRoot, "src", "Auth.DAL");
        char separator = Path.DirectorySeparatorChar;

        IEnumerable<string> offenders = Directory.EnumerateFiles(dalSource, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains(separator + "obj" + separator, StringComparison.Ordinal) && !f.Contains(separator + "bin" + separator, StringComparison.Ordinal))
            .SelectMany(f => banned.Where(api => File.ReadAllText(f).Contains(api, StringComparison.Ordinal)).Select(api => Path.GetFileName(f) + ": " + api));

        Assert.NotEmpty(Directory.EnumerateFiles(dalSource, "*Repository.cs", SearchOption.AllDirectories));
        Assert.Empty(offenders);
    }

    [Fact]
    public void No_pluralizer_is_referenced()
    {
        IEnumerable<string> pluralizers = Dal.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.Contains("Humanizer", StringComparison.OrdinalIgnoreCase) || n.Contains("Pluraliz", StringComparison.OrdinalIgnoreCase));

        Assert.Empty(pluralizers);
    }

    private static IEnumerable<Type> BaseTypesAndInterfaces(Type type)
    {
        for (Type? current = type.BaseType; current is not null; current = current.BaseType)
        {
            yield return current;
        }

        foreach (Type contract in type.GetInterfaces())
        {
            yield return contract;
        }
    }

    private static bool IsEfType(Type type) =>
        (type.Namespace ?? string.Empty).StartsWith(EfNamespace, StringComparison.Ordinal)
        || (type.IsGenericType && type.GetGenericArguments().Any(IsEfType));
}
