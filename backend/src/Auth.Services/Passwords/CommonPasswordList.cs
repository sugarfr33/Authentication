using System.Reflection;
using System.Text;

namespace Auth.Services.Passwords;

/// <summary>
/// The embedded top-100,000 common password list (see docs/third-party-data.md), loaded once on first use into a
/// case-insensitive set. Registered as a singleton.
/// </summary>
internal sealed class CommonPasswordList
{
    public const string ResourceName = "Auth.Services.Passwords.common-passwords.txt";

    private readonly Lazy<HashSet<string>> entries = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    public int Count => entries.Value.Count;

    /// <summary>Case-insensitive (ordinal) membership test on the NFKC-normalized candidate.</summary>
    public bool Contains(string normalizedPassword) => entries.Value.Contains(normalizedPassword);

    private static HashSet<string> Load()
    {
        using Stream stream = typeof(CommonPasswordList).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("Embedded resource missing: " + ResourceName);
        using StreamReader reader = new(stream, Encoding.UTF8);

        HashSet<string> set = new(StringComparer.OrdinalIgnoreCase);
        for (string? line = reader.ReadLine(); line is not null; line = reader.ReadLine())
        {
            string entry = line.Trim();
            if (entry.Length > 0)
            {
                set.Add(entry.Normalize(NormalizationForm.FormKC));
            }
        }

        return set;
    }
}
