using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using TfmAudit.Analysis;

namespace TfmAudit.Reporting;

/// <summary>
/// Самодостаточный HTML-отчёт: шаблон лежит в ресурсах сборки, данные подставляются
/// в него как JSON. Никаких внешних скриптов и стилей — файл можно переслать и открыть офлайн.
/// </summary>
public static class HtmlReporter
{
    private const string ResourceName = "TfmAudit.Reporting.Templates.report.html";
    private const string Placeholder = "/*__PAYLOAD__*/";

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Render(AuditReport report)
    {
        var template = LoadTemplate();
        var payload = BuildPayload(report);

        var index = template.IndexOf(Placeholder, StringComparison.Ordinal);
        if (index < 0)
            throw new InvalidOperationException("В шаблоне HTML-отчёта не найден маркер для данных.");

        return template.Substring(0, index) + payload + template.Substring(index + Placeholder.Length);
    }

    private static string LoadTemplate()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Ресурс {ResourceName} не найден в сборке.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string BuildPayload(AuditReport report)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, WriterOptions))
        {
            w.WriteStartObject();
            w.WriteString("tool", "tfm-audit");
            w.WriteString("version", report.ToolVersion);
            w.WriteString("generatedAt", report.GeneratedAt.ToString("dd.MM.yyyy HH:mm"));
            w.WriteBoolean("online", report.OnlineMode);

            w.WriteStartArray("sources");
            foreach (var s in report.Sources) w.WriteStringValue(s);
            w.WriteEndArray();

            w.WriteStartArray("notes");
            foreach (var n in report.Notes) w.WriteStringValue(n);
            w.WriteEndArray();

            w.WriteStartArray("projects");
            foreach (var p in report.Projects)
            {
                w.WriteStartObject();
                w.WriteString("name", p.Name);
                w.WriteString("assetsPath", p.AssetsPath);
                w.WriteString("projectPath", p.ProjectPath ?? string.Empty);

                w.WriteStartArray("frameworks");
                foreach (var fw in p.Frameworks) WriteFramework(w, fw);
                w.WriteEndArray();

                w.WriteEndObject();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        }

        var json = Encoding.UTF8.GetString(buffer.ToArray());

        // Внутри <script type="application/json"> недопустимы последовательности вида "</script>",
        // поэтому экранируем угловые скобки и амперсанд — для JSON это законные escape-последовательности.
        return json
            .Replace("<", "\\u003c", StringComparison.Ordinal)
            .Replace(">", "\\u003e", StringComparison.Ordinal)
            .Replace("&", "\\u0026", StringComparison.Ordinal);
    }

    private static void WriteFramework(Utf8JsonWriter w, FrameworkAnalysis fw)
    {
        w.WriteStartObject();
        w.WriteString("alias", fw.Alias);
        w.WriteString("tfm", fw.Tfm.ShortName);
        w.WriteString("tfmDisplay", fw.Tfm.DisplayName);
        w.WriteBoolean("assetTargetFallback", fw.AssetTargetFallback);

        w.WriteStartArray("imports");
        foreach (var i in fw.Imports) w.WriteStringValue(i);
        w.WriteEndArray();

        w.WriteStartObject("stats");
        w.WriteNumber("packages", fw.PackageCount);
        w.WriteNumber("projectRefs", fw.ProjectReferenceCount);
        w.WriteNumber("direct", fw.DirectDependencies.Count);
        w.WriteNumber("upToDate", fw.UpToDateCount);
        w.WriteNumber("assetless", fw.AssetlessCount);
        w.WriteNumber("error", fw.Findings.Count(f => f.Severity == Severity.Error));
        w.WriteNumber("warning", fw.Findings.Count(f => f.Severity == Severity.Warning));
        w.WriteNumber("info", fw.Findings.Count(f => f.Severity == Severity.Info));
        w.WriteNumber("singleOwner", fw.FindingsWithSingleOwner);
        w.WriteNumber("manyOwners", fw.FindingsWithManyOwners);
        w.WriteEndObject();

        w.WriteStartArray("histogram");
        foreach (var kv in fw.AssetTfmHistogram.OrderByDescending(x => x.Value).ThenBy(x => x.Key, StringComparer.Ordinal))
        {
            w.WriteStartArray();
            w.WriteStringValue(kv.Key);
            w.WriteNumberValue(kv.Value);
            w.WriteEndArray();
        }

        w.WriteEndArray();

        w.WriteStartArray("plan");
        foreach (var r in fw.Recommendations)
        {
            w.WriteStartObject();
            w.WriteNumber("order", r.Order);
            w.WriteString("id", r.RootId);
            w.WriteString("version", r.RootVersion);
            w.WriteString("range", r.RequestedRange ?? string.Empty);
            w.WriteBoolean("itselfOutdated", r.RootIsItselfOutdated);
            w.WriteBoolean("auto", r.AutoReferenced);
            w.WriteBoolean("projectRef", r.IsProjectReference);
            w.WriteString("upgrade", r.Upgrade is not null && r.Upgrade.Outcome != UpgradeOutcome.NotChecked ? r.Upgrade.Render() : string.Empty);

            w.WriteStartArray("covers");
            foreach (var c in r.Covers) w.WriteStringValue(c);
            w.WriteEndArray();

            w.WriteStartArray("exclusive");
            foreach (var c in r.CoversExclusively) w.WriteStringValue(c);
            w.WriteEndArray();

            w.WriteEndObject();
        }

        w.WriteEndArray();

        w.WriteStartArray("findings");
        foreach (var f in fw.Findings)
        {
            w.WriteStartObject();
            w.WriteString("id", f.PackageId);
            w.WriteString("version", f.PackageVersion);
            w.WriteString("sev", f.Severity.Code());
            w.WriteString("kind", f.Kind.ToString());
            w.WriteString("assetTfm", f.WorstAssetTfm.ShortName);
            w.WriteNumber("behind", f.GenerationsBehind);
            w.WriteNumber("depth", f.Depth);
            w.WriteBoolean("direct", f.IsDirect);
            w.WriteString("explanation", f.Explanation);
            w.WriteString("hint", f.Redundancy?.Note ?? string.Empty);
            w.WriteString("upgrade", f.Upgrade is not null && f.Upgrade.Outcome != UpgradeOutcome.NotChecked ? f.Upgrade.Render() : string.Empty);

            w.WriteStartArray("assets");
            foreach (var a in f.Evidence)
            {
                w.WriteStartObject();
                w.WriteString("g", a.Group);
                w.WriteString("p", a.Path);
                w.WriteEndObject();
            }

            w.WriteEndArray();

            w.WriteStartArray("roots");
            foreach (var r in f.ReachedFromRoots) w.WriteStringValue(r);
            w.WriteEndArray();

            w.WriteStartArray("chains");
            foreach (var chain in f.Chains)
            {
                w.WriteStartArray();
                foreach (var step in chain.Steps)
                {
                    w.WriteStartObject();
                    w.WriteString("id", step.Id);
                    w.WriteString("v", step.Version);
                    w.WriteString("r", step.RequestedRange ?? string.Empty);
                    w.WriteEndObject();
                }

                w.WriteEndArray();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        }

        w.WriteEndArray();

        // Граф: узлы по индексам, рёбра — компактными массивами.
        var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < fw.Graph.Nodes.Count; i++) index[fw.Graph.Nodes[i].Id] = i;

        w.WriteStartObject("graph");
        w.WriteStartArray("nodes");
        foreach (var n in fw.Graph.Nodes)
        {
            w.WriteStartObject();
            w.WriteString("id", n.Id);
            w.WriteString("v", n.Version);
            w.WriteString("tfm", n.AssetTfm);
            w.WriteString("sev", n.Severity);
            w.WriteBoolean("d", n.IsDirect);
            w.WriteBoolean("p", n.IsProject);
            w.WriteNumber("depth", n.Depth);
            w.WriteEndObject();
        }

        w.WriteEndArray();

        w.WriteStartArray("edges");
        foreach (var e in fw.Graph.Edges)
        {
            if (!index.TryGetValue(e.From, out var from) || !index.TryGetValue(e.To, out var to)) continue;
            w.WriteStartArray();
            w.WriteNumberValue(from);
            w.WriteNumberValue(to);
            w.WriteNumberValue(e.OnProblemPath ? 1 : 0);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteEndObject();

        w.WriteEndObject();
    }
}
