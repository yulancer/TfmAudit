using TfmAudit.Model;

namespace TfmAudit.Analysis;

public sealed class AnalyzerOptions
{
    /// <summary>Анализировать только эти таргеты (короткие имена). Пусто — все.</summary>
    public List<string> OnlyFrameworks { get; } = new();

    /// <summary>Считать netstandard2.x предупреждением, а не информацией.</summary>
    public bool NetStandardAsWarning { get; set; }

    /// <summary>Сколько цепочек показывать на находку.</summary>
    public int MaxChainsPerFinding { get; set; } = 3;

    /// <summary>Не отбрасывать находки ниже этого уровня.</summary>
    public Severity MinSeverity { get; set; } = Severity.Info;

    /// <summary>Игнорировать пакеты по id (поддерживается «*» на конце).</summary>
    public List<string> IgnorePackages { get; } = new();
}

/// <summary>
/// Ядро анализа. Для каждого таргета из assets-файла строит граф зависимостей,
/// находит пакеты, чьи выбранные ассеты относятся к более раннему поколению, чем сам таргет,
/// и объясняет, какая прямая зависимость их притащила.
/// </summary>
public sealed class TfmAnalyzer
{
    private readonly AnalyzerOptions _options;

    public TfmAnalyzer(AnalyzerOptions options)
    {
        _options = options;
    }

    public ProjectAnalysis Analyze(AssetsFile assets)
    {
        var project = new ProjectAnalysis(assets.DisplayName, assets.Path, assets.ProjectFilePath);

        foreach (var target in assets.Targets.Values.OrderBy(t => t.Alias, StringComparer.OrdinalIgnoreCase))
        {
            if (_options.OnlyFrameworks.Count > 0 &&
                !_options.OnlyFrameworks.Any(f =>
                    f.Equals(target.Alias, StringComparison.OrdinalIgnoreCase) ||
                    f.Equals(target.Tfm.ShortName, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            project.Frameworks.Add(AnalyzeTarget(assets, target));
        }

        return project;
    }

    private FrameworkAnalysis AnalyzeTarget(AssetsFile assets, TargetSection target)
    {
        var fa = new FrameworkAnalysis(target.Alias, target.Tfm);

        assets.Frameworks.TryGetValue(target.Alias, out var projectFramework);
        if (projectFramework is null)
        {
            // Алиас таргета может быть с RID («net8.0/win-x64») — ищем по короткому имени.
            projectFramework = assets.Frameworks.Values
                .FirstOrDefault(f => f.Tfm.ShortName.Equals(target.Tfm.ShortName, StringComparison.OrdinalIgnoreCase));
        }

        var libs = target.LibrariesById;
        fa.PackageCount = libs.Values.Count(l => !l.IsProject);
        fa.ProjectReferenceCount = libs.Values.Count(l => l.IsProject);

        if (projectFramework is not null)
        {
            fa.AssetTargetFallback = projectFramework.AssetTargetFallback;
            fa.Imports.AddRange(projectFramework.Imports);
            fa.DirectDependencies.AddRange(projectFramework.Dependencies.Values.OrderBy(d => d.Id, StringComparer.OrdinalIgnoreCase));

            // ProjectReference — такая же прямая зависимость проекта, как PackageReference.
            foreach (var name in projectFramework.ProjectReferenceNames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
            {
                if (!libs.TryGetValue(name, out var projectLib)) continue;
                if (projectFramework.Dependencies.ContainsKey(projectLib.Id)) continue;
                fa.DirectDependencies.Add(new DirectDependency(projectLib.Id, null, "Project", false, null));
            }
        }

        // Нормализованный граф: ключи зависимостей в assets пишутся в регистре nuspec-а
        // ссылающегося пакета, поэтому приводим их к каноническому Id библиотеки.
        var adjacency = new Dictionary<string, List<DependencyEdge>>(StringComparer.OrdinalIgnoreCase);
        var inDegree = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var lib in libs.Values) inDegree[lib.Id] = 0;

        foreach (var lib in libs.Values)
        {
            var edges = new List<DependencyEdge>();
            foreach (var dep in lib.Dependencies)
            {
                if (!libs.TryGetValue(dep.Key, out var resolved)) continue;
                if (resolved.Id.Equals(lib.Id, StringComparison.OrdinalIgnoreCase)) continue;
                edges.Add(new DependencyEdge(resolved.Id, string.IsNullOrEmpty(dep.Value) ? null : dep.Value));
                inDegree[resolved.Id] = inDegree[resolved.Id] + 1;
            }

            adjacency[lib.Id] = edges;
        }

        // ---- 1. Классификация каждого пакета ----
        var classified = new Dictionary<string, PackageClassification>(StringComparer.OrdinalIgnoreCase);
        foreach (var lib in libs.Values)
        {
            var c = Classify(lib, target.Tfm);
            classified[lib.Id] = c;

            var bucket = c.WorstTfm?.ShortName ?? "—";
            fa.AssetTfmHistogram[bucket] = fa.AssetTfmHistogram.TryGetValue(bucket, out var n) ? n + 1 : 1;

            if (c.WorstTfm is null) fa.AssetlessCount++;
            else if (c.Kind is null) fa.UpToDateCount++;
        }

        // ---- 2. Корни графа: прямые PackageReference, ProjectReference и всё, на что никто не ссылается ----
        var roots = new List<string>();

        foreach (var dep in fa.DirectDependencies)
            if (libs.TryGetValue(dep.Id, out var directLib)) roots.Add(directLib.Id);

        if (roots.Count == 0 && assets.ProjectFileDependencyGroups.TryGetValue(target.Alias, out var group))
        {
            foreach (var line in group)
            {
                var id = line.Split(new[] { ' ', '>', '=', '<', '[', '(' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (id is not null && libs.TryGetValue(id, out var fromGroup)) roots.Add(fromGroup.Id);
            }
        }

        // Без этого шага пакеты, попавшие в граф только через ProjectReference более глубокого
        // уровня (или циклический фрагмент), остались бы без объяснения «кто их притащил».
        foreach (var lib in libs.Values)
            if (inDegree[lib.Id] == 0) roots.Add(lib.Id);

        var declaredDirect = new HashSet<string>(
            fa.DirectDependencies.Where(d => libs.ContainsKey(d.Id)).Select(d => libs[d.Id].Id),
            StringComparer.OrdinalIgnoreCase);

        roots = roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        roots.Sort(StringComparer.OrdinalIgnoreCase);

        // ---- 3. Глубины от проекта ----
        var depth = ComputeDepths(adjacency, roots);

        // ---- 4. Достижимость и кратчайшие пути от каждого корня ----
        var reachableFrom = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var predecessorsFrom = new Dictionary<string, Dictionary<string, string?>>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            var preds = Bfs(adjacency, root);
            predecessorsFrom[root] = preds;
            reachableFrom[root] = new HashSet<string>(preds.Keys, StringComparer.OrdinalIgnoreCase);
        }

        // ---- 5. Находки ----
        var edgesOnProblemPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var findingsById = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);

        foreach (var lib in libs.Values.OrderBy(l => l.Id, StringComparer.OrdinalIgnoreCase))
        {
            var c = classified[lib.Id];
            if (c.Kind is null || c.Severity is null) continue;
            if (lib.IsProject) continue;
            if (IsIgnored(lib.Id)) continue;
            if (c.Severity.Value < _options.MinSeverity) continue;

            var reachingRoots = roots
                .Where(r => r.Equals(lib.Id, StringComparison.OrdinalIgnoreCase) || reachableFrom[r].Contains(lib.Id))
                .OrderBy(r => r, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var chains = new List<DependencyChain>();
            foreach (var root in reachingRoots)
            {
                var chain = BuildChain(libs, adjacency, predecessorsFrom[root], root, lib.Id);
                if (chain is not null) chains.Add(chain);
            }

            chains = chains
                .OrderBy(ch => ch.Length)
                .ThenBy(ch => ch.RootId, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var chain in chains.Take(Math.Max(1, _options.MaxChainsPerFinding)))
            {
                for (var i = 0; i + 1 < chain.Steps.Count; i++)
                    edgesOnProblemPaths.Add($"{chain.Steps[i].Id}->{chain.Steps[i + 1].Id}");
            }

            var finding = new Finding(
                lib.Id,
                lib.Version,
                c.Kind.Value,
                c.Severity.Value,
                target.Tfm,
                c.WorstTfm!,
                c.WorstTfm!.Family == target.Tfm.Family ? c.WorstTfm.MajorGenerationsBehind(target.Tfm) : 0,
                c.Evidence,
                declaredDirect.Contains(lib.Id),
                reachingRoots,
                chains.Take(Math.Max(1, _options.MaxChainsPerFinding)).ToList(),
                FrameworkProvidedPackages.TryGetHint(lib.Id, target.Tfm),
                depth.TryGetValue(lib.Id, out var d) ? d : 0);

            findingsById[lib.Id] = finding;
            fa.Findings.Add(finding);
        }

        fa.Findings.Sort(CompareFindings);

        // ---- 6. Рекомендации: какие прямые зависимости обновлять ----
        BuildRecommendations(fa, libs, roots, reachableFrom, findingsById, projectFramework);

        // ---- 7. Слепок графа ----
        fa.Graph = BuildGraph(libs, adjacency, classified, findingsById, declaredDirect, depth, edgesOnProblemPaths);

        return fa;
    }

    private static int CompareFindings(Finding a, Finding b)
    {
        var bySeverity = b.Severity.CompareTo(a.Severity);
        if (bySeverity != 0) return bySeverity;

        var byGap = b.GenerationsBehind.CompareTo(a.GenerationsBehind);
        if (byGap != 0) return byGap;

        var byDepth = a.Depth.CompareTo(b.Depth);
        if (byDepth != 0) return byDepth;

        return string.Compare(a.PackageId, b.PackageId, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsIgnored(string id)
    {
        foreach (var pattern in _options.IgnorePackages)
        {
            if (pattern.EndsWith("*", StringComparison.Ordinal))
            {
                if (id.StartsWith(pattern.Substring(0, pattern.Length - 1), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (id.Equals(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------------ классификация

    private sealed class PackageClassification
    {
        public Tfm? WorstTfm;
        public FindingKind? Kind;
        public Severity? Severity;
        public List<AssetEvidence> Evidence = new();
        public bool OnlyBuildAssets;
    }

    private PackageClassification Classify(TargetLibrary lib, Tfm target)
    {
        var result = new PackageClassification();

        var parsed = new List<AssetPathInfo>();
        foreach (var group in lib.AssetGroups)
        {
            foreach (var path in group.Value)
                parsed.Add(AssetPathParser.Parse(group.Key, path));
        }

        var withTfm = parsed.Where(p => p.Tfm is not null && !p.IsPlaceholder && !p.Tfm!.IsAgnostic).ToList();

        var codeAssets = withTfm.Where(p => AssetPathParser.IsCodeGroup(p.Group)).ToList();
        var relevant = codeAssets.Count > 0 ? codeAssets : withTfm;
        result.OnlyBuildAssets = codeAssets.Count == 0 && withTfm.Count > 0;

        if (relevant.Count == 0)
        {
            // Ассетов, привязанных к TFM, нет: аналайзеры, метапакеты, контент.
            if (lib.FrameworkAssemblies.Count > 0 && target.Family == TfmFamily.NetCoreApp)
            {
                result.WorstTfm = Tfm.Parse("net48");
                result.Kind = FindingKind.FrameworkAssemblyReference;
                result.Severity = Analysis.Severity.Warning;
                result.Evidence = lib.FrameworkAssemblies
                    .Select(a => new AssetEvidence("frameworkAssemblies", a, result.WorstTfm!))
                    .ToList();
            }

            return result;
        }

        // «Худший» ассет: сначала по семейству (чужое хуже своего), потом по версии.
        var worst = relevant
            .OrderByDescending(p => FamilyPenalty(p.Tfm!, target))
            .ThenBy(p => p.Tfm!.Version)
            .First();

        result.WorstTfm = worst.Tfm;
        result.Evidence = relevant
            .Where(p => p.Tfm!.Equals(worst.Tfm!))
            .OrderBy(p => p.Group, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
            .Select(p => new AssetEvidence(p.Group, p.Path, p.Tfm!))
            .ToList();

        var worstTfm = worst.Tfm!;

        if (worstTfm.Family == target.Family)
        {
            var gap = worstTfm.MajorGenerationsBehind(target);
            if (gap <= 0 && worstTfm.Version >= target.Version)
                return result; // всё в порядке

            if (gap <= 0)
            {
                // Тот же мажор, но минорная версия ниже (net6.0 под net6.1 — практически не встречается).
                result.Kind = FindingKind.LowerGeneration;
                result.Severity = Analysis.Severity.Info;
            }
            else
            {
                result.Kind = FindingKind.LowerGeneration;
                result.Severity = gap >= 2 ? Analysis.Severity.Error : Analysis.Severity.Warning;
            }
        }
        else if (worstTfm.Family == TfmFamily.NetStandard && target.Family == TfmFamily.NetCoreApp)
        {
            result.Kind = FindingKind.NetStandardAsset;
            result.Severity = worstTfm.Version.Major <= 1
                ? Analysis.Severity.Warning
                : (_options.NetStandardAsWarning ? Analysis.Severity.Warning : Analysis.Severity.Info);
        }
        else if (worstTfm.Family is TfmFamily.NetFramework or TfmFamily.PortableProfile && target.Family == TfmFamily.NetCoreApp)
        {
            result.Kind = FindingKind.ForeignFamilyAsset;
            result.Severity = Analysis.Severity.Error;
        }
        else if (worstTfm.Family == TfmFamily.NetCoreApp && target.Family == TfmFamily.NetFramework)
        {
            result.Kind = FindingKind.ForeignFamilyAsset;
            result.Severity = Analysis.Severity.Error;
        }
        else
        {
            return result;
        }

        // Если пострадали только MSBuild-ассеты, а скомпилированный код берётся из актуальной папки —
        // это слабее на один уровень.
        if (result.OnlyBuildAssets && result.Severity > Analysis.Severity.Info)
            result.Severity = result.Severity.Value - 1;

        return result;
    }

    /// <summary>Насколько «чужим» является семейство ассета относительно таргета. Больше — хуже.</summary>
    private static int FamilyPenalty(Tfm asset, Tfm target)
    {
        if (asset.Family == target.Family) return 0;
        return asset.Family switch
        {
            TfmFamily.NetStandard => 1,
            TfmFamily.PortableProfile => 3,
            TfmFamily.NetFramework => 3,
            TfmFamily.NetCoreApp => 3,
            _ => 2,
        };
    }

    // ------------------------------------------------------------------ граф

    private static Dictionary<string, int> ComputeDepths(
        Dictionary<string, List<DependencyEdge>> adjacency,
        List<string> roots)
    {
        var depth = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>();

        foreach (var r in roots)
        {
            if (!adjacency.ContainsKey(r) || depth.ContainsKey(r)) continue;
            depth[r] = 1;
            queue.Enqueue(r);
        }

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!adjacency.TryGetValue(current, out var edges)) continue;

            foreach (var edge in edges)
            {
                if (depth.ContainsKey(edge.To)) continue;
                depth[edge.To] = depth[current] + 1;
                queue.Enqueue(edge.To);
            }
        }

        return depth;
    }

    /// <summary>BFS от одного узла. Возвращает «узел → предшественник» (у стартового — null).</summary>
    private static Dictionary<string, string?> Bfs(
        Dictionary<string, List<DependencyEdge>> adjacency,
        string start)
    {
        var preds = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!adjacency.ContainsKey(start)) return preds;

        preds[start] = null;
        var queue = new Queue<string>();
        queue.Enqueue(start);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!adjacency.TryGetValue(current, out var edges)) continue;

            foreach (var edge in edges)
            {
                if (preds.ContainsKey(edge.To)) continue;
                preds[edge.To] = current;
                queue.Enqueue(edge.To);
            }
        }

        return preds;
    }

    private static DependencyChain? BuildChain(
        Dictionary<string, TargetLibrary> libs,
        Dictionary<string, List<DependencyEdge>> adjacency,
        Dictionary<string, string?> preds,
        string root,
        string targetId)
    {
        if (!preds.ContainsKey(targetId)) return null;

        var reverse = new List<string>();
        var cursor = targetId;
        var guard = 0;
        while (cursor is not null)
        {
            reverse.Add(cursor);
            if (cursor.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
            if (!preds.TryGetValue(cursor, out var prev) || prev is null) break;
            cursor = prev;
            if (++guard > 512) break;
        }

        reverse.Reverse();

        var steps = new List<ChainStep>(reverse.Count);
        for (var i = 0; i < reverse.Count; i++)
        {
            var id = reverse[i];
            libs.TryGetValue(id, out var lib);
            string? range = null;
            if (i > 0 && adjacency.TryGetValue(reverse[i - 1], out var parentEdges))
            {
                range = parentEdges
                    .FirstOrDefault(e => e.To.Equals(id, StringComparison.OrdinalIgnoreCase))?.Range;
            }

            steps.Add(new ChainStep(lib?.Id ?? id, lib?.Version ?? string.Empty, range));
        }

        return new DependencyChain(steps);
    }

    private static GraphSnapshot BuildGraph(
        Dictionary<string, TargetLibrary> libs,
        Dictionary<string, List<DependencyEdge>> adjacency,
        Dictionary<string, PackageClassification> classified,
        Dictionary<string, Finding> findings,
        HashSet<string> declaredDirect,
        Dictionary<string, int> depth,
        HashSet<string> problemEdges)
    {
        var snapshot = new GraphSnapshot();

        foreach (var lib in libs.Values.OrderBy(l => l.Id, StringComparer.OrdinalIgnoreCase))
        {
            classified.TryGetValue(lib.Id, out var c);
            findings.TryGetValue(lib.Id, out var finding);

            snapshot.Nodes.Add(new GraphNode(
                lib.Id,
                lib.Version,
                c?.WorstTfm?.ShortName ?? "—",
                finding is null ? "ok" : finding.Severity.Code(),
                declaredDirect.Contains(lib.Id),
                lib.IsProject,
                depth.TryGetValue(lib.Id, out var d) ? d : 0,
                finding is not null));
        }

        foreach (var kv in adjacency)
        {
            foreach (var edge in kv.Value)
            {
                snapshot.Edges.Add(new GraphEdge(
                    kv.Key,
                    edge.To,
                    edge.Range,
                    problemEdges.Contains($"{kv.Key}->{edge.To}")));
            }
        }

        return snapshot;
    }

    // ------------------------------------------------------------------ рекомендации

    private void BuildRecommendations(
        FrameworkAnalysis fa,
        Dictionary<string, TargetLibrary> libs,
        List<string> roots,
        Dictionary<string, HashSet<string>> reachableFrom,
        Dictionary<string, Finding> findings,
        ProjectFramework? projectFramework)
    {
        if (findings.Count == 0) return;

        var findingIds = new HashSet<string>(findings.Keys, StringComparer.OrdinalIgnoreCase);

        // Что закрывает каждый корень.
        var covers = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (findingIds.Contains(root)) set.Add(root);
            foreach (var id in reachableFrom[root])
                if (findingIds.Contains(id)) set.Add(id);

            if (set.Count > 0) covers[root] = set;
        }

        // Эксклюзивные находки: их закроет только этот корень.
        var ownerCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var set in covers.Values)
        {
            foreach (var id in set)
                ownerCount[id] = ownerCount.TryGetValue(id, out var n) ? n + 1 : 1;
        }

        var exclusive = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in covers)
        {
            exclusive[kv.Key] = kv.Value
                .Where(id => ownerCount.TryGetValue(id, out var n) && n == 1)
                .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        // Находка исчезает только тогда, когда обновлены ВСЕ прямые зависимости, через которые
        // она достижима. Поэтому «минимальное покрытие» здесь было бы обманом: считаем влияние.
        fa.FindingsWithSingleOwner = findingIds.Count(id => ownerCount.TryGetValue(id, out var n) && n == 1);
        fa.FindingsWithManyOwners = findingIds.Count(id => ownerCount.TryGetValue(id, out var n) && n > 1);

        foreach (var kv in covers)
        {
            var root = kv.Key;
            libs.TryGetValue(root, out var lib);
            DirectDependency? dd = null;
            if (projectFramework is not null && projectFramework.Dependencies.TryGetValue(root, out var found)) dd = found;

            fa.Recommendations.Add(new Recommendation(
                root,
                lib?.Version ?? string.Empty,
                dd?.VersionRange,
                dd?.AutoReferenced ?? false,
                findingIds.Contains(root),
                lib?.IsProject ?? false,
                kv.Value.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
                exclusive.TryGetValue(root, out var ex) ? ex : new List<string>(),
                0));
        }

        // Приоритет: сначала те, у кого больше «эксклюзивных» находок (гарантированный выигрыш),
        // затем по общему влиянию.
        fa.Recommendations.Sort((a, b) =>
        {
            var byExclusive = b.CoversExclusively.Count.CompareTo(a.CoversExclusively.Count);
            if (byExclusive != 0) return byExclusive;

            var byCount = b.Covers.Count.CompareTo(a.Covers.Count);
            if (byCount != 0) return byCount;

            return string.Compare(a.RootId, b.RootId, StringComparison.OrdinalIgnoreCase);
        });

        for (var i = 0; i < fa.Recommendations.Count; i++)
            fa.Recommendations[i].Order = i + 1;
    }
}

/// <summary>Ребро графа с уже приведённым к каноническому виду идентификатором цели.</summary>
public sealed class DependencyEdge
{
    public DependencyEdge(string to, string? range)
    {
        To = to;
        Range = range;
    }

    public string To { get; }

    /// <summary>Диапазон версий, как его запросил родительский пакет.</summary>
    public string? Range { get; }
}
