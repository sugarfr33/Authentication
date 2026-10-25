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
    [InlineData("Auth.Client", new[] { "Auth.Contracts" })]
    [InlineData("Auth.SampleApi", new[] { "Auth.Client" })]
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
    [InlineData("Auth.Client")]
    [InlineData("Auth.SampleApi")]
    public void Only_DAL_references_EntityFrameworkCore_packages(string project)
    {
        IEnumerable<string> packages = XDocument.Load(RepoPaths.ProjectFile(project))
            .Descendants("PackageReference")
            .Select(p => (string?)p.Attribute("Include") ?? string.Empty);

        Assert.DoesNotContain(packages, p => p.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>T22: the client library adds exactly one package (the approved IdentityModel family) and the shared framework.</summary>
    [Fact]
    public void The_client_library_uses_only_the_approved_token_package()
    {
        XDocument project = XDocument.Load(RepoPaths.ProjectFile("Auth.Client"));

        Assert.Equal(["Microsoft.IdentityModel.JsonWebTokens"], project.Descendants("PackageReference").Select(p => (string?)p.Attribute("Include")));
        Assert.Equal(["Microsoft.AspNetCore.App"], project.Descendants("FrameworkReference").Select(p => (string?)p.Attribute("Include")));
    }

    /// <summary>T22: library code awaits with ConfigureAwait(false); the build enforces CA2007 for Auth.Client only.</summary>
    [Fact]
    public void CA2007_is_an_error_for_the_client_library_only()
    {
        string[] lines = File.ReadAllLines(Path.Combine(RepoPaths.RepoRoot, ".editorconfig"));
        int section = Array.IndexOf(lines, "[backend/src/Auth.Client/**.cs]");

        Assert.True(section >= 0, "the Auth.Client section is missing from .editorconfig");
        Assert.Equal("dotnet_diagnostic.CA2007.severity = error", lines[section + 1].Trim());
        Assert.Single(lines, l => l.Contains("CA2007", StringComparison.Ordinal));
    }

    private static IEnumerable<string> ReadProjectReferences(string project) =>
        XDocument.Load(RepoPaths.ProjectFile(project))
            .Descendants("ProjectReference")
            .Select(r => Path.GetFileNameWithoutExtension(((string?)r.Attribute("Include") ?? string.Empty).Replace('\\', '/')));
}
