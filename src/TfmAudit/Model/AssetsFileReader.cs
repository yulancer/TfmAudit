using System.Text.Json;

namespace TfmAudit.Model;

/// <summary>Читает project.assets.json (формат NuGet версии 3) в модель <see cref="AssetsFile"/>.</summary>
public static class AssetsFileReader
{
    /// <summary>Секции ассетов, которые нас интересуют. Порядок важен для отчёта.</summary>
    public static readonly string[] AssetGroupNames =
    {
        "compile",
        "runtime",
        "runtimeTargets",
        "resource",
        "native",
        "embed",
        "build",
        "buildMultiTargeting",
        "buildTransitive",
        "contentFiles",
        "tools",
    };

    public static AssetsFile Read(string path)
    {
        using var stream = File.OpenRead(path);
        using var doc = JsonDocument.Parse(stream, new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
        });

        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException($"{path}: ожидался JSON-объект на верхнем уровне.");

        var result = new AssetsFile(Path.GetFullPath(path));

        if (root.TryGetProperty("version", out var ver) && ver.ValueKind == JsonValueKind.Number)
            result.FormatVersion = ver.GetInt32();

        ReadProjectSection(root, result);
        ReadTargets(root, result);
        ReadLibraries(root, result);
        ReadProjectFileDependencyGroups(root, result);

        if (result.Targets.Count == 0)
            throw new InvalidDataException($"{path}: секция \"targets\" пуста или отсутствует — это не похоже на project.assets.json.");

        return result;
    }

    private static void ReadProjectSection(JsonElement root, AssetsFile result)
    {
        if (!root.TryGetProperty("project", out var project) || project.ValueKind != JsonValueKind.Object)
            return;

        if (project.TryGetProperty("version", out _))
        {
            // project/version — версия пакета, не формата. Не используем.
        }

        var restoreProjectRefs = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        if (project.TryGetProperty("restore", out var restore) && restore.ValueKind == JsonValueKind.Object)
        {
            result.ProjectName = GetString(restore, "projectName");
            result.ProjectFilePath = GetString(restore, "projectPath") ?? GetString(restore, "projectUniqueName");
            result.ProjectStyle = GetString(restore, "projectStyle");

            if (restore.TryGetProperty("frameworks", out var restoreFrameworks) && restoreFrameworks.ValueKind == JsonValueKind.Object)
            {
                foreach (var rf in restoreFrameworks.EnumerateObject())
                {
                    if (rf.Value.ValueKind != JsonValueKind.Object) continue;
                    if (!rf.Value.TryGetProperty("projectReferences", out var refs) || refs.ValueKind != JsonValueKind.Object)
                        continue;

                    var paths = refs.EnumerateObject().Select(p => p.Name).ToList();
                    restoreProjectRefs[rf.Name] = paths;

                    var alias = GetString(rf.Value, "targetAlias");
                    if (!string.IsNullOrEmpty(alias)) restoreProjectRefs[alias!] = paths;
                }
            }
        }

        if (!project.TryGetProperty("frameworks", out var frameworks) || frameworks.ValueKind != JsonValueKind.Object)
            return;

        foreach (var fw in frameworks.EnumerateObject())
        {
            var pf = new ProjectFramework(fw.Name, Tfm.Parse(fw.Name));

            if (fw.Value.ValueKind != JsonValueKind.Object)
            {
                result.Frameworks[fw.Name] = pf;
                continue;
            }

            if (fw.Value.TryGetProperty("dependencies", out var deps) && deps.ValueKind == JsonValueKind.Object)
            {
                foreach (var dep in deps.EnumerateObject())
                {
                    string? range = null, target = null, suppress = null;
                    var auto = false;
                    if (dep.Value.ValueKind == JsonValueKind.Object)
                    {
                        range = GetString(dep.Value, "version");
                        target = GetString(dep.Value, "target");
                        suppress = GetString(dep.Value, "suppressParent");
                        if (dep.Value.TryGetProperty("autoReferenced", out var ar) &&
                            (ar.ValueKind == JsonValueKind.True || ar.ValueKind == JsonValueKind.False))
                        {
                            auto = ar.GetBoolean();
                        }
                    }

                    pf.Dependencies[dep.Name] = new DirectDependency(dep.Name, range, target, auto, suppress);
                }
            }

            if (fw.Value.TryGetProperty("imports", out var imports) && imports.ValueKind == JsonValueKind.Array)
            {
                foreach (var imp in imports.EnumerateArray())
                {
                    if (imp.ValueKind == JsonValueKind.String)
                    {
                        var s = imp.GetString();
                        if (!string.IsNullOrEmpty(s)) pf.Imports.Add(s!);
                    }
                }
            }

            if (fw.Value.TryGetProperty("assetTargetFallback", out var atf) &&
                (atf.ValueKind == JsonValueKind.True || atf.ValueKind == JsonValueKind.False))
            {
                pf.AssetTargetFallback = atf.GetBoolean();
            }

            if (fw.Value.TryGetProperty("frameworkReferences", out var fr) && fr.ValueKind == JsonValueKind.Object)
            {
                foreach (var r in fr.EnumerateObject()) pf.FrameworkReferences.Add(r.Name);
            }

            result.Frameworks[fw.Name] = pf;
        }
    }

    private static void ReadTargets(JsonElement root, AssetsFile result)
    {
        if (!root.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object)
            return;

        foreach (var target in targets.EnumerateObject())
        {
            var section = new TargetSection(target.Name, Tfm.Parse(target.Name));
            if (target.Value.ValueKind != JsonValueKind.Object)
            {
                result.Targets[target.Name] = section;
                continue;
            }

            foreach (var lib in target.Value.EnumerateObject())
            {
                var key = lib.Name;
                var slash = key.LastIndexOf('/');
                var id = slash > 0 ? key.Substring(0, slash) : key;
                var version = slash > 0 ? key.Substring(slash + 1) : string.Empty;
                var type = (lib.Value.ValueKind == JsonValueKind.Object ? GetString(lib.Value, "type") : null) ?? "package";

                var entry = new TargetLibrary(key, id, version, type);

                if (lib.Value.ValueKind == JsonValueKind.Object)
                {
                    if (lib.Value.TryGetProperty("dependencies", out var deps) && deps.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var d in deps.EnumerateObject())
                            entry.Dependencies[d.Name] = d.Value.ValueKind == JsonValueKind.String ? (d.Value.GetString() ?? string.Empty) : string.Empty;
                    }

                    foreach (var groupName in AssetGroupNames)
                    {
                        if (!lib.Value.TryGetProperty(groupName, out var group) || group.ValueKind != JsonValueKind.Object)
                            continue;

                        var paths = new List<string>();
                        foreach (var p in group.EnumerateObject())
                            paths.Add(p.Name);

                        if (paths.Count > 0)
                            entry.AssetGroups[groupName] = paths;
                    }

                    if (lib.Value.TryGetProperty("frameworkAssemblies", out var fa) && fa.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var a in fa.EnumerateArray())
                        {
                            if (a.ValueKind == JsonValueKind.String)
                            {
                                var s = a.GetString();
                                if (!string.IsNullOrEmpty(s)) entry.FrameworkAssemblies.Add(s!);
                            }
                        }
                    }

                    if (lib.Value.TryGetProperty("frameworkReferences", out var fr) && fr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var a in fr.EnumerateArray())
                        {
                            if (a.ValueKind == JsonValueKind.String)
                            {
                                var s = a.GetString();
                                if (!string.IsNullOrEmpty(s)) entry.FrameworkReferences.Add(s!);
                            }
                        }
                    }
                }

                section.LibrariesByKey[key] = entry;
                section.LibrariesById[id] = entry;
            }

            result.Targets[target.Name] = section;
        }
    }

    private static void ReadLibraries(JsonElement root, AssetsFile result)
    {
        if (!root.TryGetProperty("libraries", out var libraries) || libraries.ValueKind != JsonValueKind.Object)
            return;

        foreach (var lib in libraries.EnumerateObject())
        {
            if (lib.Value.ValueKind != JsonValueKind.Object) continue;
            var type = GetString(lib.Value, "type");
            if (type is not null) result.LibraryTypes[lib.Name] = type;
            var p = GetString(lib.Value, "path");
            if (p is not null) result.LibraryPaths[lib.Name] = p;
        }
    }

    private static void ReadProjectFileDependencyGroups(JsonElement root, AssetsFile result)
    {
        if (!root.TryGetProperty("projectFileDependencyGroups", out var groups) || groups.ValueKind != JsonValueKind.Object)
            return;

        foreach (var g in groups.EnumerateObject())
        {
            var list = new List<string>();
            if (g.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in g.Value.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var s = item.GetString();
                        if (!string.IsNullOrEmpty(s)) list.Add(s!);
                    }
                }
            }

            result.ProjectFileDependencyGroups[g.Name] = list;
        }
    }

    private static string? GetString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
