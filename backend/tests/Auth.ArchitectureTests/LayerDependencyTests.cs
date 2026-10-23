using System.Reflection;
using NetArchTest.Rules;

namespace Auth.ArchitectureTests;

/// <summary>Compiled assemblies (IL) must respect the layer rules, whatever the csproj files say.</summary>
public class LayerDependencyTests
{
    private const string EfCore = "Microsoft.EntityFrameworkCore";

    private static readonly Assembly Api = typeof(Auth.Api.AssemblyMarker).Assembly;
    private static readonly Assembly Services = typeof(Auth.Services.AssemblyMarker).Assembly;
    private static readonly Assembly Dal = typeof(Auth.DAL.AssemblyMarker).Assembly;
    private static readonly Assembly Entities = typeof(Auth.Entities.AssemblyMarker).Assembly;
    private static readonly Assembly Contracts = typeof(Auth.Contracts.AssemblyMarker).Assembly;

    public static TheoryData<string, string[]> ForbiddenDependencies => new()
    {
        { "Auth.Api", ["Auth.DAL", "Auth.Entities", EfCore] },
        { "Auth.Services", [EfCore, "Auth.Api"] },
        { "Auth.DAL", ["Auth.Services", "Auth.Contracts", "Auth.Api"] },
        { "Auth.Entities", ["Auth.DAL", "Auth.Services", "Auth.Contracts", "Auth.Api", EfCore] },
        { "Auth.Contracts", ["Auth.Entities", "Auth.DAL", "Auth.Services", "Auth.Api", EfCore] },
    };

    [Theory]
    [MemberData(nameof(ForbiddenDependencies))]
    public void Types_do_not_depend_on_forbidden_layers(string assemblyName, string[] forbidden)
    {
        var result = Types.InAssembly(Resolve(assemblyName))
            .ShouldNot()
            .HaveDependencyOnAny(forbidden)
            .GetResult();

        Assert.True(result.IsSuccessful, "Offending types: " + string.Join(", ", result.FailingTypeNames ?? []));
    }

    [Theory]
    [MemberData(nameof(ForbiddenDependencies))]
    public void Assembly_does_not_reference_forbidden_assemblies(string assemblyName, string[] forbidden)
    {
        var referenced = Resolve(assemblyName).GetReferencedAssemblies().Select(a => a.Name ?? string.Empty);

        Assert.DoesNotContain(referenced, r => forbidden.Any(f => r.StartsWith(f, StringComparison.Ordinal)));
    }

    private static Assembly Resolve(string name) => name switch
    {
        "Auth.Api" => Api,
        "Auth.Services" => Services,
        "Auth.DAL" => Dal,
        "Auth.Entities" => Entities,
        "Auth.Contracts" => Contracts,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };
}
