using System.Text.Json;

namespace Auth.ArchitectureTests;

/// <summary>T09: committed appsettings hold no secrets (they come from environment variables or User Secrets) and no wildcard hosts.</summary>
public class AppSettingsSecretsTests
{
    private static readonly string[] SecretSections = ["ConnectionStrings", "Secrets", "SecretFiles"];

    [Theory]
    [InlineData("appsettings.json")]
    [InlineData("appsettings.Development.json")]
    public void Committed_settings_contain_no_secrets(string fileName)
    {
        string text = File.ReadAllText(Path.Combine(RepoPaths.BackendRoot, "src", "Auth.Api", fileName));
        using JsonDocument document = JsonDocument.Parse(text);

        IEnumerable<string> present = document.RootElement.EnumerateObject().Select(p => p.Name).Intersect(SecretSections);

        Assert.Empty(present);
        Assert.DoesNotContain("Password=", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("appsettings.json")]
    [InlineData("appsettings.Example.json")]
    public void AllowedHosts_is_not_a_wildcard(string fileName)
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoPaths.BackendRoot, "src", "Auth.Api", fileName)));

        string? hosts = document.RootElement.GetProperty("AllowedHosts").GetString();

        Assert.False(string.IsNullOrWhiteSpace(hosts));
        Assert.DoesNotContain("*", hosts, StringComparison.Ordinal);
    }
}
