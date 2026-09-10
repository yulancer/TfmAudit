using System.Text.Encodings.Web;
using System.Text.Json;
using TfmAudit.Analysis;

namespace TfmAudit.Reporting;

/// <summary>Машиночитаемый отчёт для CI.</summary>
public static class JsonReporter
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Render(AuditReport report)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, WriterOptions))
        {
            w.WriteStartObject();
            w.WriteString("tool", "tfm-audit");
            w.WriteString("toolVersion", report.ToolVersion);
            w.WriteString("generatedAt", report.GeneratedAt.ToString("O"));
            w.WriteBoolean("onlineMode", report.OnlineMode);

            w.WriteStartArray("sources");
            foreach (var s in report.Sources) w.WriteStringValue(s);
            w.WriteEndArray();

            w.WriteStartArray("notes");
            foreach (var n in report.Notes) w.WriteStringValue(n);
            w.WriteEndArray();

            w.WriteStartObject("totals");
            w.WriteNumber("error", CountBy(report, Severity.Error));
            w.WriteNumber("warning", CountBy(report, Severity.Warning));
            w.WriteNumber("info", CountBy(report, Severity.Info));
            w.WriteEndObject();

            w.WriteStartArray("projects");
            foreach (var p in report.Projects) WriteProject(w, p);
            w.WriteEndArray();

            w.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static int CountBy(AuditReport report, Severity s) =>
        report.Projects.SelectMany(p => p.Frameworks).SelectMany(f => f.Findings).Count(f => f.Severity == s);

    private static void WriteProject(Utf8JsonWriter w, ProjectAnalysis p)
    {
        w.WriteStartObject();
        w.WriteString("name", p.Name);
        w.WriteString("assetsPath", p.AssetsPath);
        if (p.ProjectPath is not null) w.WriteString("projectPath", p.ProjectPath);

        w.WriteStartArray("frameworks");
        foreach (var fw in p.Frameworks) WriteFramework(w, fw);
        w.WriteEndArray();

        w.WriteEndObject();
    }

    private static void WriteFramework(Utf8JsonWriter w, FrameworkAnalysis fw)
    {
        w.WriteStartObject();
        w.WriteString("alias", fw.Alias);
        w.WriteString("tfm", fw.Tfm.ShortName);
        w.WriteString("tfmDisplay", fw.Tfm.DisplayName);
        w.WriteNumber("packageCount", fw.PackageCount);
        w.WriteNumber("projectReferenceCount", fw.ProjectReferenceCount);
        w.WriteNumber("upToDateCount", fw.UpToDateCount);
        w.WriteNumber("assetlessCount", fw.AssetlessCount);
        w.WriteBoolean("assetTargetFallback", fw.AssetTargetFallback);

        w.WriteStartObject("assetTfmHistogram");
        foreach (var kv in fw.AssetTfmHistogram.OrderByDescending(x => x.Value)) w.WriteNumber(kv.Key, kv.Value);
        w.WriteEndObject();

        w.WriteStartArray("recommendations");
        foreach (var r in fw.Recommendations)
        {
            w.WriteStartObject();
            w.WriteNumber("order", r.Order);
            w.WriteString("packageId", r.RootId);
            w.WriteString("resolvedVersion", r.RootVersion);
            if (r.RequestedRange is not null) w.WriteString("requestedRange", r.RequestedRange);
            w.WriteBoolean("autoReferenced", r.AutoReferenced);
            w.WriteBoolean("itselfOutdated", r.RootIsItselfOutdated);
            w.WriteNumber("coversCount", r.Covers.Count);
            w.WriteStartArray("covers");
            foreach (var c in r.Covers) w.WriteStringValue(c);
            w.WriteEndArray();
            w.WriteStartArray("coversExclusively");
            foreach (var c in r.CoversExclusively) w.WriteStringValue(c);
            w.WriteEndArray();
            WriteUpgrade(w, r.Upgrade);
            w.WriteEndObject();
        }

        w.WriteEndArray();

        w.WriteStartArray("findings");
        foreach (var f in fw.Findings)
        {
            w.WriteStartObject();
            w.WriteString("packageId", f.PackageId);
            w.WriteString("packageVersion", f.PackageVersion);
            w.WriteString("severity", f.Severity.Code());
            w.WriteString("kind", f.Kind.ToString());
            w.WriteString("targetTfm", f.TargetTfm.ShortName);
            w.WriteString("assetTfm", f.WorstAssetTfm.ShortName);
            w.WriteNumber("generationsBehind", f.GenerationsBehind);
            w.WriteNumber("depth", f.Depth);
            w.WriteBoolean("isDirect", f.IsDirect);
            w.WriteString("explanation", f.Explanation);

            w.WriteStartArray("assets");
            foreach (var ev in f.Evidence)
            {
                w.WriteStartObject();
                w.WriteString("group", ev.Group);
                w.WriteString("path", ev.Path);
                w.WriteString("tfm", ev.Tfm.ShortName);
                w.WriteEndObject();
            }

            w.WriteEndArray();

            w.WriteStartArray("reachedFromRoots");
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
                    w.WriteString("version", step.Version);
                    if (step.RequestedRange is not null) w.WriteString("requestedRange", step.RequestedRange);
                    w.WriteEndObject();
                }

                w.WriteEndArray();
            }

            w.WriteEndArray();

            if (f.Redundancy is not null)
            {
                w.WriteStartObject("redundancy");
                w.WriteString("kind", f.Redundancy.Kind.ToString());
                w.WriteString("note", f.Redundancy.Note);
                w.WriteEndObject();
            }

            WriteUpgrade(w, f.Upgrade);
            w.WriteEndObject();
        }

        w.WriteEndArray();
        w.WriteEndObject();
    }

    private static void WriteUpgrade(Utf8JsonWriter w, UpgradeAdvice? advice)
    {
        if (advice is null || advice.Outcome == UpgradeOutcome.NotChecked) return;

        w.WriteStartObject("upgrade");
        w.WriteString("outcome", advice.Outcome.ToString());
        if (advice.MinimumSupportingVersion is not null) w.WriteString("minimumSupportingVersion", advice.MinimumSupportingVersion);
        if (advice.LatestStableVersion is not null) w.WriteString("latestStableVersion", advice.LatestStableVersion);
        if (advice.LatestVersion is not null) w.WriteString("latestVersion", advice.LatestVersion);
        if (advice.Source is not null) w.WriteString("source", advice.Source);
        if (advice.DetectionMethod is not null) w.WriteString("detectionMethod", advice.DetectionMethod);
        if (advice.Message is not null) w.WriteString("message", advice.Message);
        w.WriteString("text", advice.Render());
        w.WriteStartArray("supportedTfms");
        foreach (var t in advice.SupportedTfms) w.WriteStringValue(t);
        w.WriteEndArray();
        w.WriteEndObject();
    }
}
