using System.Xml.Linq;

namespace Auth.ArchitectureTests;

/// <summary>Declared project references must match the dependency rules exactly (T01 acceptance).</summary>
public class ProjectReferenceTests
{
    [Theory]
    [InlineData("Auth.Api", new[] { "Auth.Contracts", "Auth.Services" })]
    [InlineData("Auth.Services", new[] { "Auth.Contracts", "Auth.DAL", "Auth.Entities" })]
    [InlineData("Auth.DAL", new[] { "Auth.Entities" })]
    [InlineData("Auth.Entities", new string[0])]
    [InlineData("Auth.Contracts", new string[0])]
    public void Project_references_match_dependency_rules(string project, string[] expected)
    {
        IEnumerable<string> actual = ReadProjectReferences(project);

        Assert.Equal(expected.Order(StringComparer.Ordinal), actual.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("Auth.Api")]
    [InlineData("Auth.Services")]
    [InlineData("Auth.Entities")]
    [InlineData("Auth.Contracts")]
    public void Only_DAL_references_EntityFrameworkCore_packages(string project)
    {
        IEnumerable<string> packages = XDocument.Load(RepoPaths.ProjectFile(project))
            .Descendants("PackageReference")
            .Select(p => (string?)p.Attribute("Include") ?? string.Empty);

        Assert.DoesNotContain(packages, p => p.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> ReadProjectReferences(string project) =>
        XDocument.Load(RepoPaths.ProjectFile(project))
            .Descendants("ProjectReference")
            .Select(r => Path.GetFileNameWithoutExtension(((string?)r.Attribute("Include") ?? string.Empty).Replace('\\', '/')));
}
