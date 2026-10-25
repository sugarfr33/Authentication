namespace Auth.ArchitectureTests;

internal static class RepoPaths
{
    /// <summary>Walks up from the test output folder to the directory holding Auth.sln.</summary>
    public static string BackendRoot { get; } = FindBackendRoot();

    /// <summary>The project file under src/, or under samples/ for the sample projects (T22).</summary>
    public static string ProjectFile(string projectName)
    {
        string src = Path.Combine(BackendRoot, "src", projectName, projectName + ".csproj");
        return File.Exists(src) ? src : Path.Combine(BackendRoot, "samples", projectName, projectName + ".csproj");
    }

    /// <summary>The repository root (the folder holding backend/ and .editorconfig).</summary>
    public static string RepoRoot => Path.GetDirectoryName(BackendRoot)!;

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
