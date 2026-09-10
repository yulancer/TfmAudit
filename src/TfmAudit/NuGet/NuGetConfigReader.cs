using System.Xml.Linq;

namespace TfmAudit.NuGet;

public sealed class PackageSource
{
    public PackageSource(string name, string url)
    {
        Name = name;
        Url = url;
    }

    public string Name { get; }

    public string Url { get; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public override string ToString() => $"{Name} ({Url})";
}

/// <summary>
/// Читает NuGet.config: поднимается от папки с assets-файлом до корня диска,
/// затем добавляет пользовательский конфиг. Учитывает &lt;clear/&gt;, disabledPackageSources
/// и packageSourceCredentials с ClearTextPassword.
/// </summary>
public static class NuGetConfigReader
{
    private static readonly string[] FileNames = { "nuget.config", "NuGet.config", "NuGet.Config" };

    public static List<PackageSource> Discover(string startDirectory, TextWriter? log = null)
    {
        var files = new List<string>();

        var dir = new DirectoryInfo(Path.GetFullPath(startDirectory));
        while (dir is not null)
        {
            foreach (var name in FileNames)
            {
                var candidate = Path.Combine(dir.FullName, name);
                if (File.Exists(candidate) && !files.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                {
                    files.Add(candidate);
                    break;
                }
            }

            dir = dir.Parent;
        }

        var userConfig = UserConfigPath();
        if (userConfig is not null && File.Exists(userConfig)) files.Add(userConfig);

        // Более специфичный конфиг (ближе к проекту) применяется последним и перекрывает общий.
        files.Reverse();

        var sources = new Dictionary<string, PackageSource>(StringComparer.OrdinalIgnoreCase);
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var credentials = new Dictionary<string, (string? User, string? Pass)>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            try
            {
                var doc = XDocument.Load(file);
                var root = doc.Root;
                if (root is null) continue;

                var packageSources = root.Elements("packageSources").FirstOrDefault();
                if (packageSources is not null)
                {
                    if (packageSources.Elements("clear").Any()) sources.Clear();

                    foreach (var add in packageSources.Elements("add"))
                    {
                        var key = add.Attribute("key")?.Value;
                        var value = add.Attribute("value")?.Value;
                        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value)) continue;
                        sources[key!] = new PackageSource(key!, value!.Trim());
                    }
                }

                var disabledSection = root.Elements("disabledPackageSources").FirstOrDefault();
                if (disabledSection is not null)
                {
                    foreach (var add in disabledSection.Elements("add"))
                    {
                        var key = add.Attribute("key")?.Value;
                        var value = add.Attribute("value")?.Value;
                        if (string.IsNullOrWhiteSpace(key)) continue;
                        if (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)) disabled.Add(key!);
                        else disabled.Remove(key!);
                    }
                }

                var credSection = root.Elements("packageSourceCredentials").FirstOrDefault();
                if (credSection is not null)
                {
                    foreach (var sourceElement in credSection.Elements())
                    {
                        var name = sourceElement.Name.LocalName.Replace("_x0020_", " ");
                        string? user = null, pass = null;
                        foreach (var add in sourceElement.Elements("add"))
                        {
                            var key = add.Attribute("key")?.Value ?? string.Empty;
                            var value = add.Attribute("value")?.Value;
                            if (key.Equals("Username", StringComparison.OrdinalIgnoreCase)) user = value;
                            else if (key.Equals("ClearTextPassword", StringComparison.OrdinalIgnoreCase)) pass = value;
                        }

                        if (user is not null || pass is not null) credentials[name] = (user, pass);
                    }
                }
            }
            catch (Exception ex)
            {
                log?.WriteLine($"  ! не удалось прочитать {file}: {ex.Message}");
            }
        }

        var result = new List<PackageSource>();
        foreach (var s in sources.Values)
        {
            if (disabled.Contains(s.Name)) continue;
            if (credentials.TryGetValue(s.Name, out var c))
            {
                s.Username = c.User;
                s.Password = c.Pass;
            }

            result.Add(s);
        }

        return result;
    }

    private static string? UserConfigPath()
    {
        if (OperatingSystem.IsWindows())
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return string.IsNullOrEmpty(appData) ? null : Path.Combine(appData, "NuGet", "NuGet.Config");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home)) return null;
        return Path.Combine(home, ".nuget", "NuGet", "NuGet.Config");
    }
}
