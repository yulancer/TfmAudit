using TfmAudit.Model;

namespace TfmAudit.Analysis;

public enum Severity
{
    Info = 0,
    Warning = 1,
    Error = 2,
}

public static class SeverityText
{
    public static string Ru(this Severity s) => s switch
    {
        Severity.Error => "ошибка",
        Severity.Warning => "предупреждение",
        _ => "информация",
    };

    public static string Code(this Severity s) => s switch
    {
        Severity.Error => "error",
        Severity.Warning => "warning",
        _ => "info",
    };

    public static bool TryParse(string text, out Severity severity)
    {
        switch ((text ?? string.Empty).Trim().ToLowerInvariant())
        {
            case "error":
            case "err":
            case "ошибка":
                severity = Severity.Error;
                return true;
            case "warning":
            case "warn":
            case "предупреждение":
                severity = Severity.Warning;
                return true;
            case "info":
            case "information":
            case "информация":
                severity = Severity.Info;
                return true;
            default:
                severity = Severity.Info;
                return false;
        }
    }
}

/// <summary>Категория находки.</summary>
public enum FindingKind
{
    /// <summary>Ассет того же семейства, но более раннего поколения: lib/net6.0 под таргетом net8.0.</summary>
    LowerGeneration,

    /// <summary>Ассет из .NET Standard под .NET-таргетом: формально совместим, но пакет давно не обновлялся.</summary>
    NetStandardAsset,

    /// <summary>Ассет другого семейства (.NET Framework, portable) подтянут через AssetTargetFallback.</summary>
    ForeignFamilyAsset,

    /// <summary>Пакет ссылается на сборки .NET Framework через frameworkAssemblies.</summary>
    FrameworkAssemblyReference,
}

/// <summary>Один ассет, из-за которого пакет попал в находки.</summary>
public sealed class AssetEvidence
{
    public AssetEvidence(string group, string path, Tfm tfm)
    {
        Group = group;
        Path = path;
        Tfm = tfm;
    }

    public string Group { get; }

    public string Path { get; }

    public Tfm Tfm { get; }
}

/// <summary>Путь от проекта до проблемного пакета.</summary>
public sealed class DependencyChain
{
    public DependencyChain(IReadOnlyList<ChainStep> steps)
    {
        Steps = steps;
    }

    public IReadOnlyList<ChainStep> Steps { get; }

    /// <summary>Прямая зависимость проекта, с которой начинается путь.</summary>
    public string RootId => Steps.Count > 0 ? Steps[0].Id : string.Empty;

    public int Length => Steps.Count;

    public string Render(string separator = " → ") =>
        string.Join(separator, Steps.Select(s => s.Version.Length > 0 ? $"{s.Id} {s.Version}" : s.Id));
}

public sealed class ChainStep
{
    public ChainStep(string id, string version, string? requestedRange)
    {
        Id = id;
        Version = version;
        RequestedRange = requestedRange;
    }

    public string Id { get; }

    public string Version { get; }

    /// <summary>Диапазон, который запросил предыдущий узел («[6.0.0, )»).</summary>
    public string? RequestedRange { get; }
}

/// <summary>Находка: конкретный пакет с устаревшим ассетом внутри конкретного таргета.</summary>
public sealed class Finding
{
    public Finding(
        string packageId,
        string packageVersion,
        FindingKind kind,
        Severity severity,
        Tfm targetTfm,
        Tfm worstAssetTfm,
        int generationsBehind,
        IReadOnlyList<AssetEvidence> evidence,
        bool isDirect,
        IReadOnlyList<string> reachedFromRoots,
        IReadOnlyList<DependencyChain> chains,
        RedundancyHint? redundancy,
        int depth)
    {
        PackageId = packageId;
        PackageVersion = packageVersion;
        Kind = kind;
        Severity = severity;
        TargetTfm = targetTfm;
        WorstAssetTfm = worstAssetTfm;
        GenerationsBehind = generationsBehind;
        Evidence = evidence;
        IsDirect = isDirect;
        ReachedFromRoots = reachedFromRoots;
        Chains = chains;
        Redundancy = redundancy;
        Depth = depth;
    }

    public string PackageId { get; }

    public string PackageVersion { get; }

    public FindingKind Kind { get; }

    public Severity Severity { get; }

    public Tfm TargetTfm { get; }

    /// <summary>Самый старый TFM среди ассетов, выбранных под этот таргет.</summary>
    public Tfm WorstAssetTfm { get; }

    /// <summary>На сколько мажорных поколений ассет отстаёт от таргета (только внутри одного семейства).</summary>
    public int GenerationsBehind { get; }

    public IReadOnlyList<AssetEvidence> Evidence { get; }

    /// <summary>Пакет прописан прямо в csproj для этого таргета.</summary>
    public bool IsDirect { get; }

    /// <summary>Прямые зависимости проекта, из которых достижим этот пакет.</summary>
    public IReadOnlyList<string> ReachedFromRoots { get; }

    /// <summary>Пути от проекта до пакета (кратчайший — первым).</summary>
    public IReadOnlyList<DependencyChain> Chains { get; }

    /// <summary>Подсказка «пакет входит в рантайм / это старый контракт».</summary>
    public RedundancyHint? Redundancy { get; }

    /// <summary>Глубина в графе: 1 — прямая зависимость.</summary>
    public int Depth { get; }

    /// <summary>Совет по обновлению из NuGet-фида (заполняется только в режиме --online).</summary>
    public UpgradeAdvice? Upgrade { get; set; }

    public string Key => $"{PackageId}/{PackageVersion}";

    public string Explanation => Kind switch
    {
        FindingKind.LowerGeneration =>
            $"Под таргетом {TargetTfm.DisplayName} пакет отдаёт ассеты для {WorstAssetTfm.DisplayName} — " +
            $"это {GenerationsBehind} {Plural(GenerationsBehind, "мажорное поколение", "мажорных поколения", "мажорных поколений")} назад.",
        FindingKind.NetStandardAsset =>
            $"Под таргетом {TargetTfm.DisplayName} используется ассет {WorstAssetTfm.DisplayName}. " +
            "Формально совместимо, но означает, что пакет собирался ещё до появления текущего таргета.",
        FindingKind.ForeignFamilyAsset =>
            $"Под таргетом {TargetTfm.DisplayName} подставлен ассет {WorstAssetTfm.DisplayName} из другого семейства — " +
            "такое возможно только через AssetTargetFallback и работает не гарантированно.",
        _ =>
            "Пакет ссылается на сборки .NET Framework (frameworkAssemblies) — на .NET Core/.NET 5+ такие ссылки не разрешаются.",
    };

    private static string Plural(int n, string one, string few, string many)
    {
        var mod10 = Math.Abs(n) % 10;
        var mod100 = Math.Abs(n) % 100;
        if (mod10 == 1 && mod100 != 11) return one;
        if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
        return many;
    }
}

/// <summary>Рекомендация: какую прямую зависимость обновить и что это закроет.</summary>
public sealed class Recommendation
{
    public Recommendation(
        string rootId,
        string rootVersion,
        string? requestedRange,
        bool autoReferenced,
        bool rootIsItselfOutdated,
        bool isProjectReference,
        IReadOnlyList<string> covers,
        IReadOnlyList<string> coversExclusively,
        int order)
    {
        RootId = rootId;
        RootVersion = rootVersion;
        RequestedRange = requestedRange;
        AutoReferenced = autoReferenced;
        RootIsItselfOutdated = rootIsItselfOutdated;
        IsProjectReference = isProjectReference;
        Covers = covers;
        CoversExclusively = coversExclusively;
        Order = order;
    }

    /// <summary>Это ProjectReference, а не NuGet-пакет: обновлять надо сам проект, фид тут не поможет.</summary>
    public bool IsProjectReference { get; }

    public string RootId { get; }

    public string RootVersion { get; }

    public string? RequestedRange { get; }

    public bool AutoReferenced { get; }

    /// <summary>Сама прямая зависимость тоже отдаёт устаревший ассет.</summary>
    public bool RootIsItselfOutdated { get; }

    /// <summary>Ключи находок, достижимых из этой прямой зависимости.</summary>
    public IReadOnlyList<string> Covers { get; }

    /// <summary>Находки, которые больше ниоткуда не достижимы — их закроет только обновление этого пакета.</summary>
    public IReadOnlyList<string> CoversExclusively { get; }

    /// <summary>Приоритет обновления: 1 — наибольшее влияние (больше всего «эксклюзивных» находок).</summary>
    public int Order { get; set; }

    public UpgradeAdvice? Upgrade { get; set; }
}

/// <summary>Результат по одному таргету.</summary>
public sealed class FrameworkAnalysis
{
    public FrameworkAnalysis(string alias, Tfm tfm)
    {
        Alias = alias;
        Tfm = tfm;
    }

    public string Alias { get; }

    public Tfm Tfm { get; }

    public List<Finding> Findings { get; } = new();

    public List<Recommendation> Recommendations { get; } = new();

    /// <summary>Прямые зависимости проекта для этого таргета.</summary>
    public List<DirectDependency> DirectDependencies { get; } = new();

    public int PackageCount { get; set; }

    public int ProjectReferenceCount { get; set; }

    /// <summary>Сколько пакетов отдают ассет ровно под целевой TFM.</summary>
    public int UpToDateCount { get; set; }

    /// <summary>Сколько пакетов вообще не имеют TFM-зависимых ассетов (аналайзеры, метапакеты).</summary>
    public int AssetlessCount { get; set; }

    /// <summary>Распределение «худший TFM ассета» → количество пакетов.</summary>
    public Dictionary<string, int> AssetTfmHistogram { get; } = new(StringComparer.Ordinal);

    /// <summary>Находки, достижимые ровно из одной прямой зависимости — их снимет одно обновление.</summary>
    public int FindingsWithSingleOwner { get; set; }

    /// <summary>Находки, достижимые из нескольких прямых зависимостей — нужно обновить все.</summary>
    public int FindingsWithManyOwners { get; set; }

    /// <summary>Включён ли AssetTargetFallback — тогда несовместимые ассеты подставляются молча.</summary>
    public bool AssetTargetFallback { get; set; }

    public List<string> Imports { get; } = new();

    /// <summary>Полный граф для визуализации.</summary>
    public GraphSnapshot Graph { get; set; } = new();

    public int CountAtLeast(Severity s) => Findings.Count(f => f.Severity >= s);
}

/// <summary>Слепок графа для отчётов (HTML/DOT/DGML).</summary>
public sealed class GraphSnapshot
{
    public List<GraphNode> Nodes { get; } = new();

    public List<GraphEdge> Edges { get; } = new();
}

public sealed class GraphNode
{
    public GraphNode(string id, string version, string assetTfm, string severity, bool isDirect, bool isProject, int depth, bool isFinding)
    {
        Id = id;
        Version = version;
        AssetTfm = assetTfm;
        Severity = severity;
        IsDirect = isDirect;
        IsProject = isProject;
        Depth = depth;
        IsFinding = isFinding;
    }

    public string Id { get; }

    public string Version { get; }

    /// <summary>Худший TFM выбранных ассетов, «—» если ассетов нет.</summary>
    public string AssetTfm { get; }

    public string Severity { get; }

    public bool IsDirect { get; }

    public bool IsProject { get; }

    public int Depth { get; }

    public bool IsFinding { get; }
}

public sealed class GraphEdge
{
    public GraphEdge(string from, string to, string? range, bool onProblemPath)
    {
        From = from;
        To = to;
        Range = range;
        OnProblemPath = onProblemPath;
    }

    public string From { get; }

    public string To { get; }

    public string? Range { get; }

    /// <summary>Ребро лежит хотя бы на одном кратчайшем пути до находки.</summary>
    public bool OnProblemPath { get; }
}

/// <summary>Результат по одному проекту (одному project.assets.json).</summary>
public sealed class ProjectAnalysis
{
    public ProjectAnalysis(string name, string assetsPath, string? projectPath)
    {
        Name = name;
        AssetsPath = assetsPath;
        ProjectPath = projectPath;
    }

    public string Name { get; }

    public string AssetsPath { get; }

    public string? ProjectPath { get; }

    public List<FrameworkAnalysis> Frameworks { get; } = new();

    public int CountAtLeast(Severity s) => Frameworks.Sum(f => f.CountAtLeast(s));
}

/// <summary>Полный отчёт.</summary>
public sealed class AuditReport
{
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.Now;

    public string ToolVersion { get; set; } = "1.0.0";

    public List<ProjectAnalysis> Projects { get; } = new();

    public List<string> Notes { get; } = new();

    public bool OnlineMode { get; set; }

    public List<string> Sources { get; } = new();

    public int CountAtLeast(Severity s) => Projects.Sum(p => p.CountAtLeast(s));

    public Severity MaxSeverity =>
        Projects.SelectMany(p => p.Frameworks).SelectMany(f => f.Findings)
            .Select(f => f.Severity)
            .DefaultIfEmpty(Severity.Info)
            .Max();

    public bool HasAnyFinding => Projects.SelectMany(p => p.Frameworks).Any(f => f.Findings.Count > 0);
}
