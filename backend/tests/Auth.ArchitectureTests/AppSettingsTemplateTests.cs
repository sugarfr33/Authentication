using System.Text.Json;

namespace Auth.ArchitectureTests;

/// <summary>The committed appsettings template must stay valid JSON so it can be copied as-is.</summary>
public class AppSettingsTemplateTests
{
    private static readonly string TemplatePath =
        Path.Combine(RepoPaths.BackendRoot, "src", "Auth.Api", "appsettings.Example.json");

    [Fact]
    public void Example_appsettings_is_valid_json()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(TemplatePath));

        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }

    [Fact]
    public void Example_connection_string_targets_local_SQLEXPRESS_instance()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(TemplatePath));

        string? connectionString = document.RootElement
            .GetProperty("ConnectionStrings")
            .GetProperty("CentralAuth")
            .GetString();

        Assert.StartsWith(@"Server=.\SQLEXPRESS;", connectionString);
    }
}
