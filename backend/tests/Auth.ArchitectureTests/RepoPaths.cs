namespace Auth.ArchitectureTests;

internal static class RepoPaths
{
    /// <summary>Walks up from the test output folder to the directory holding Auth.sln.</summary>
    public static string BackendRoot { get; } = FindBackendRoot();

    public static string ProjectFile(string projectName) =>
        Path.Combine(BackendRoot, "src", projectName, projectName + ".csproj");

    private static string FindBackendRoot()
    {
        DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Auth.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Auth.sln not found above " + AppContext.BaseDirectory);
    }
}
