namespace TfmAudit.Cli;

/// <summary>Превращает пользовательский путь в список project.assets.json.</summary>
public static class AssetsLocator
{
    private const string AssetsFileName = "project.assets.json";

    public static List<string> Resolve(IEnumerable<string> inputs, bool recurse, List<string> problems)
    {
        var result = new List<string>();

        foreach (var raw in inputs)
        {
            var input = raw.Trim().Trim('"');
            var full = Path.GetFullPath(input);

            if (File.Exists(full))
            {
                var name = Path.GetFileName(full);

                if (name.Equals(AssetsFileName, StringComparison.OrdinalIgnoreCase))
                {
                    Add(result, full);
                    continue;
                }

                var ext = Path.GetExtension(full);
                if (ext.Equals(".csproj", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".fsproj", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".vbproj", StringComparison.OrdinalIgnoreCase))
                {
                    var dir = Path.GetDirectoryName(full)!;
                    var candidate = Path.Combine(dir, "obj", AssetsFileName);
                    if (File.Exists(candidate)) Add(result, candidate);
                    else problems.Add($"{input}: рядом нет obj/{AssetsFileName} — сначала выполните dotnet restore");
                    continue;
                }

                if (ext.Equals(".sln", StringComparison.OrdinalIgnoreCase))
                {
                    var dir = Path.GetDirectoryName(full)!;
                    var found = FindRecursive(dir);
                    if (found.Count == 0)
                        problems.Add($"{input}: в дереве решения не найдено ни одного {AssetsFileName} — сначала выполните dotnet restore");
                    foreach (var f in found) Add(result, f);
                    continue;
                }

                problems.Add($"{input}: не похоже ни на {AssetsFileName}, ни на файл проекта или решения");
                continue;
            }

            if (Directory.Exists(full))
            {
                var direct = Path.Combine(full, "obj", AssetsFileName);
                var here = Path.Combine(full, AssetsFileName);

                if (!recurse && File.Exists(direct)) { Add(result, direct); continue; }
                if (!recurse && File.Exists(here)) { Add(result, here); continue; }

                var found = FindRecursive(full);
                if (found.Count == 0)
                    problems.Add($"{input}: не найдено ни одного {AssetsFileName}" +
                                 (recurse ? string.Empty : " (попробуйте -r для рекурсивного поиска)"));
                foreach (var f in found) Add(result, f);
                continue;
            }

            problems.Add($"{input}: путь не найден");
        }

        return result;
    }

    private static void Add(List<string> list, string path)
    {
        if (!list.Contains(path, StringComparer.OrdinalIgnoreCase)) list.Add(path);
    }

    private static List<string> FindRecursive(string root)
    {
        var result = new List<string>();
        var skip = new[] { "bin", "node_modules", ".git", ".vs", ".idea" };

        void Walk(string dir, int depth)
        {
            if (depth > 12) return;

            try
            {
                var candidate = Path.Combine(dir, AssetsFileName);
                if (File.Exists(candidate)) result.Add(candidate);

                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    var name = Path.GetFileName(sub);
                    if (skip.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
                    Walk(sub, depth + 1);
                }
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (IOException)
            {
            }
        }

        Walk(root, 0);
        result.Sort(StringComparer.OrdinalIgnoreCase);
        return result;
    }
}
