namespace TfmAudit.Model;

/// <summary>Одна библиотека внутри секции targets/&lt;tfm&gt; в project.assets.json.</summary>
public sealed class TargetLibrary
{
    public TargetLibrary(string key, string id, string version, string type)
    {
        Key = key;
        Id = id;
        Version = version;
        Type = type;
    }

    /// <summary>Ключ как в assets-файле: «Newtonsoft.Json/13.0.4».</summary>
    public string Key { get; }

    public string Id { get; }

    public string Version { get; }

    /// <summary>«package» или «project».</summary>
    public string Type { get; }

    public bool IsProject => string.Equals(Type, "project", StringComparison.OrdinalIgnoreCase);

    /// <summary>Зависимости: id пакета → диапазон версий, как записано в assets.</summary>
    public Dictionary<string, string> Dependencies { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Пути ассетов по секциям: «compile» → [«lib/net6.0/x.dll»].</summary>
    public Dictionary<string, List<string>> AssetGroups { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ссылки на сборки .NET Framework (frameworkAssemblies) — признак фасадного пакета.</summary>
    public List<string> FrameworkAssemblies { get; } = new();

    /// <summary>Ссылки на shared framework (Microsoft.AspNetCore.App и т.п.).</summary>
    public List<string> FrameworkReferences { get; } = new();

    public IReadOnlyList<string> Assets(string group) =>
        AssetGroups.TryGetValue(group, out var list) ? list : Array.Empty<string>();
}

/// <summary>Секция targets/&lt;alias&gt;.</summary>
public sealed class TargetSection
{
    public TargetSection(string alias, Tfm tfm)
    {
        Alias = alias;
        Tfm = tfm;
    }

    public string Alias { get; }

    public Tfm Tfm { get; }

    public Dictionary<string, TargetLibrary> LibrariesByKey { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>id пакета (регистронезависимо) → библиотека. В одном таргете id уникален.</summary>
    public Dictionary<string, TargetLibrary> LibrariesById { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Прямая зависимость из project/frameworks/&lt;alias&gt;/dependencies.</summary>
public sealed class DirectDependency
{
    public DirectDependency(string id, string? versionRange, string? target, bool autoReferenced, string? suppressParent)
    {
        Id = id;
        VersionRange = versionRange;
        Target = target;
        AutoReferenced = autoReferenced;
        SuppressParent = suppressParent;
    }

    public string Id { get; }

    public string? VersionRange { get; }

    /// <summary>«Package» или «Project».</summary>
    public string? Target { get; }

    /// <summary>Пакет подтянут SDK автоматически (например, аналайзеры из Build.Sdk).</summary>
    public bool AutoReferenced { get; }

    /// <summary>Значение PrivateAssets/suppressParent, если было.</summary>
    public string? SuppressParent { get; }
}

/// <summary>Описание таргета из секции project/frameworks.</summary>
public sealed class ProjectFramework
{
    public ProjectFramework(string alias, Tfm tfm)
    {
        Alias = alias;
        Tfm = tfm;
    }

    public string Alias { get; }

    public Tfm Tfm { get; }

    public Dictionary<string, DirectDependency> Dependencies { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Список imports (PackageTargetFallback / AssetTargetFallback).</summary>
    public List<string> Imports { get; } = new();

    /// <summary>true, если imports работают как AssetTargetFallback (то есть молча подставляют несовместимые ассеты).</summary>
    public bool AssetTargetFallback { get; set; }

    public List<string> FrameworkReferences { get; } = new();

    /// <summary>
    /// Пути к csproj из project/restore/frameworks/&lt;alias&gt;/projectReferences.
    /// ProjectReference — такая же прямая зависимость проекта, как PackageReference.
    /// </summary>
    public List<string> ProjectReferencePaths { get; } = new();

    /// <summary>Имена проектов из <see cref="ProjectReferencePaths"/> (имя файла без расширения).</summary>
    public IEnumerable<string> ProjectReferenceNames =>
        ProjectReferencePaths.Select(p => System.IO.Path.GetFileNameWithoutExtension(p.Replace('\\', '/')))
            .Where(n => !string.IsNullOrEmpty(n));
}

/// <summary>Разобранный project.assets.json.</summary>
public sealed class AssetsFile
{
    public AssetsFile(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public int FormatVersion { get; set; }

    public string? ProjectName { get; set; }

    public string? ProjectFilePath { get; set; }

    public string? ProjectStyle { get; set; }

    public Dictionary<string, TargetSection> Targets { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, ProjectFramework> Frameworks { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>libraries/&lt;key&gt;/type — «package» или «project».</summary>
    public Dictionary<string, string> LibraryTypes { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>libraries/&lt;key&gt;/path — относительный путь в кеше пакетов.</summary>
    public Dictionary<string, string> LibraryPaths { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>projectFileDependencyGroups: alias → ["Name >= 1.0.0", …].</summary>
    public Dictionary<string, List<string>> ProjectFileDependencyGroups { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string DisplayName =>
        ProjectName
        ?? (ProjectFilePath is null ? null : System.IO.Path.GetFileNameWithoutExtension(ProjectFilePath))
        ?? System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(Path)) ?? Path)
        ?? "(проект)";
}
