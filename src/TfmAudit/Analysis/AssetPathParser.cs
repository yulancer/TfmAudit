using System.Text.RegularExpressions;
using TfmAudit.Model;

namespace TfmAudit.Analysis;

/// <summary>Один разобранный путь ассета.</summary>
public sealed class AssetPathInfo
{
    public AssetPathInfo(string group, string path, Tfm? tfm, string? rid, bool isPlaceholder)
    {
        Group = group;
        Path = path;
        Tfm = tfm;
        Rid = rid;
        IsPlaceholder = isPlaceholder;
    }

    /// <summary>Секция assets-файла: compile, runtime, build…</summary>
    public string Group { get; }

    public string Path { get; }

    /// <summary>TFM папки, если он в пути есть.</summary>
    public Tfm? Tfm { get; }

    /// <summary>RID для runtimes/&lt;rid&gt;/… .</summary>
    public string? Rid { get; }

    /// <summary>Путь заканчивается на «_._» — «совместим, но ассетов нет».</summary>
    public bool IsPlaceholder { get; }
}

/// <summary>Достаёт TFM из путей ассетов NuGet-пакета.</summary>
public static class AssetPathParser
{
    private static readonly Regex LibOrRef =
        new(@"^(?:lib|ref|embed)/(?<tfm>[^/]+)/", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RuntimesLib =
        new(@"^runtimes/(?<rid>[^/]+)/(?:lib|native)/(?<tfm>[^/]+)/", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex BuildFolder =
        new(@"^(?:build|buildTransitive|buildMultiTargeting|buildCrossTargeting)/(?<tfm>[^/]+)/", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex ContentFiles =
        new(@"^contentFiles/[^/]+/(?<tfm>[^/]+)/", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex ToolsFolder =
        new(@"^tools/(?<tfm>[^/]+)/", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Секции, где TFM ассета реально влияет на скомпилированный код (а не на MSBuild-логику).</summary>
    public static bool IsCodeGroup(string group) =>
        group.Equals("compile", StringComparison.OrdinalIgnoreCase) ||
        group.Equals("runtime", StringComparison.OrdinalIgnoreCase) ||
        group.Equals("runtimeTargets", StringComparison.OrdinalIgnoreCase) ||
        group.Equals("embed", StringComparison.OrdinalIgnoreCase);

    public static AssetPathInfo Parse(string group, string path)
    {
        var normalized = path.Replace('\\', '/');
        var isPlaceholder = normalized.EndsWith("/_._", StringComparison.Ordinal) ||
                            normalized.Equals("_._", StringComparison.Ordinal);

        var m = LibOrRef.Match(normalized);
        if (m.Success)
            return new AssetPathInfo(group, path, Tfm.Parse(m.Groups["tfm"].Value), null, isPlaceholder);

        m = RuntimesLib.Match(normalized);
        if (m.Success)
            return new AssetPathInfo(group, path, Tfm.Parse(m.Groups["tfm"].Value), m.Groups["rid"].Value, isPlaceholder);

        m = BuildFolder.Match(normalized);
        if (m.Success)
            return new AssetPathInfo(group, path, Tfm.Parse(m.Groups["tfm"].Value), null, isPlaceholder);

        m = ContentFiles.Match(normalized);
        if (m.Success)
            return new AssetPathInfo(group, path, Tfm.Parse(m.Groups["tfm"].Value), null, isPlaceholder);

        m = ToolsFolder.Match(normalized);
        if (m.Success)
        {
            var tfm = Tfm.Parse(m.Groups["tfm"].Value);
            // tools/any/... — не таргет.
            return new AssetPathInfo(group, path, tfm.Family == TfmFamily.Agnostic ? null : tfm, null, isPlaceholder);
        }

        // analyzers/dotnet/cs/*.dll, runtimes/<rid>/nativeassets/…, и т.п. — TFM не определён.
        return new AssetPathInfo(group, path, null, null, isPlaceholder);
    }
}
