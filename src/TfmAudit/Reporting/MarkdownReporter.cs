using System.Text;
using TfmAudit.Analysis;

namespace TfmAudit.Reporting;

/// <summary>Markdown-отчёт: то же содержимое, что в консоли, но пригодное для передачи команде.</summary>
public static class MarkdownReporter
{
    public static string Render(AuditReport report)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Аудит таргетов в графе зависимостей");
        sb.AppendLine();
        sb.AppendLine($"*Сформировано `tfm-audit {report.ToolVersion}` {report.GeneratedAt:dd.MM.yyyy HH:mm}*");
        sb.AppendLine();
        sb.AppendLine("Проверка ищет пакеты, которые под конкретным таргетом отдают ассеты более раннего");
        sb.AppendLine("поколения — например `lib/net6.0` под `net8.0` или `lib/net8.0` под `net10.0`.");
        sb.AppendLine("Каждый таргет проверяется относительно себя, поэтому мультитаргетность и условные");
        sb.AppendLine("ссылки в csproj (`Condition=\"'$(TargetFramework)'=='net6.0'\"`) находками не считаются.");
        sb.AppendLine();

        var e = Count(report, Severity.Error);
        var w = Count(report, Severity.Warning);
        var i = Count(report, Severity.Info);

        sb.AppendLine("| Уровень | Что означает | Найдено |");
        sb.AppendLine("|---|---|---:|");
        sb.AppendLine($"| **Ошибка** | ассет отстаёт от таргета на 2+ мажорных поколения, либо подставлен ассет чужого семейства | {e} |");
        sb.AppendLine($"| **Предупреждение** | ассет отстаёт на 1 поколение, либо `netstandard1.x`, либо ссылки на сборки .NET Framework | {w} |");
        sb.AppendLine($"| Информация | ассет `netstandard2.x` (совместим, но пакет старый) либо устарели только MSBuild-ассеты | {i} |");
        sb.AppendLine();

        if (report.OnlineMode)
        {
            sb.AppendLine($"Опрошенные источники NuGet: {(report.Sources.Count > 0 ? string.Join(", ", report.Sources.Select(s => $"`{s}`")) : "нет")}.");
            sb.AppendLine();
        }

        foreach (var note in report.Notes)
            sb.AppendLine($"> ⚠ {note}").AppendLine();

        foreach (var project in report.Projects)
            RenderProject(sb, project);

        sb.AppendLine("---");
        sb.AppendLine();
        sb.AppendLine("## Как читать отчёт");
        sb.AppendLine();
        sb.AppendLine("* **Ассет** — папка внутри NuGet-пакета, из которой restore взял библиотеку для данного таргета");
        sb.AppendLine("  (`lib/<tfm>/…`, `ref/<tfm>/…`, `runtimes/<rid>/lib/<tfm>/…`). NuGet выбирает наибольший TFM,");
        sb.AppendLine("  не превышающий таргет, — поэтому пакет с папками `net6.0` и без `net8.0` под таргетом `net8.0`");
        sb.AppendLine("  тихо отдаёт net6-сборку.");
        sb.AppendLine("* **Путь** — цепочка от прямой зависимости проекта до проблемного пакета. Обновлять надо");
        sb.AppendLine("  первый элемент цепочки: транзитивную версию напрямую не поднять (кроме явного пина).");
        sb.AppendLine("* **Минимальный набор** — жадное покрытие: набор прямых зависимостей, обновление которых");
        sb.AppendLine("  затрагивает все находки. Обновляйте сверху вниз, каждый раз перезапуская `dotnet restore`.");
        sb.AppendLine("* `netstandard2.0` формально совместим с любым современным .NET, но означает, что пакет");
        sb.AppendLine("  собирался ещё до появления вашего таргета: это кандидат на обновление, а не поломка.");
        sb.AppendLine();

        return sb.ToString();
    }

    private static int Count(AuditReport report, Severity s) =>
        report.Projects.SelectMany(p => p.Frameworks).SelectMany(f => f.Findings).Count(f => f.Severity == s);

    private static void RenderProject(StringBuilder sb, ProjectAnalysis project)
    {
        sb.AppendLine($"## Проект `{project.Name}`");
        sb.AppendLine();
        sb.AppendLine($"* assets: `{project.AssetsPath}`");
        if (project.ProjectPath is not null) sb.AppendLine($"* csproj: `{project.ProjectPath}`");
        sb.AppendLine($"* таргеты: {string.Join(", ", project.Frameworks.Select(f => $"`{f.Alias}`"))}");
        sb.AppendLine();

        foreach (var fw in project.Frameworks)
            RenderFramework(sb, fw);
    }

    private static void RenderFramework(StringBuilder sb, FrameworkAnalysis fw)
    {
        sb.AppendLine($"### Таргет `{fw.Alias}` — {fw.Tfm.DisplayName}");
        sb.AppendLine();

        var e = fw.Findings.Count(f => f.Severity == Severity.Error);
        var w = fw.Findings.Count(f => f.Severity == Severity.Warning);
        var i = fw.Findings.Count(f => f.Severity == Severity.Info);

        sb.AppendLine($"Пакетов в графе: **{fw.PackageCount}**" +
                      (fw.ProjectReferenceCount > 0 ? $" (+{fw.ProjectReferenceCount} project-ссылок)" : string.Empty) +
                      $" · прямых зависимостей: **{fw.DirectDependencies.Count}**" +
                      $" · ассет ровно под таргет: **{fw.UpToDateCount}**" +
                      $" · без TFM-ассетов: {fw.AssetlessCount}");
        sb.AppendLine();
        sb.AppendLine($"Находки: **{e}** ошибок · **{w}** предупреждений · {i} информационных.");
        sb.AppendLine();

        if (fw.AssetTargetFallback)
        {
            sb.AppendLine($"> ⚠ Для этого таргета включён `AssetTargetFallback`" +
                          (fw.Imports.Count > 0 ? $" (`{string.Join("`, `", fw.Imports)}`)" : string.Empty) +
                          ". Несовместимые ассеты подставляются молча, без ошибки восстановления.");
            sb.AppendLine();
        }

        if (fw.AssetTfmHistogram.Count > 0)
        {
            sb.AppendLine("<details><summary>Худший TFM выбранных ассетов, по пакетам</summary>");
            sb.AppendLine();
            sb.AppendLine("| TFM ассета | Пакетов |");
            sb.AppendLine("|---|---:|");
            foreach (var kv in fw.AssetTfmHistogram.OrderByDescending(x => x.Value).ThenBy(x => x.Key, StringComparer.Ordinal))
                sb.AppendLine($"| `{kv.Key}` | {kv.Value} |");
            sb.AppendLine();
            sb.AppendLine("</details>");
            sb.AppendLine();
        }

        if (fw.Findings.Count == 0)
        {
            sb.AppendLine("✔ Устаревших ассетов под этот таргет не найдено.");
            sb.AppendLine();
            return;
        }

        RenderPlan(sb, fw);
        RenderFindings(sb, fw);
    }

    private static void RenderPlan(StringBuilder sb, FrameworkAnalysis fw)
    {
        var plan = fw.Recommendations;
        if (plan.Count == 0) return;

        sb.AppendLine("#### Что обновить");
        sb.AppendLine();
        sb.AppendLine($"К находкам ведут {Ru.Dependencies(plan.Count)} из csproj. Транзитивную версию напрямую не поднять — " +
                      "обновлять надо тот пакет, который её тянет.");
        sb.AppendLine();
        sb.AppendLine($"* находок, достижимых ровно из одной прямой зависимости: **{fw.FindingsWithSingleOwner}** — " +
                      "их снимет одно обновление;");
        sb.AppendLine($"* находок, достижимых сразу из нескольких: **{fw.FindingsWithManyOwners}** — уйдут только " +
                      "после обновления всех перечисленных для них виновников.");
        sb.AppendLine();
        sb.AppendLine("| # | Прямая зависимость | Версия | Ведёт к находкам | Только через неё | Совет фида |");
        sb.AppendLine("|---:|---|---|---:|---:|---|");

        foreach (var r in plan)
        {
            var advice = r.Upgrade is not null && r.Upgrade.Outcome != UpgradeOutcome.NotChecked
                ? EscapeCell(r.Upgrade.Render())
                : "—";
            var name = $"`{r.RootId}`" +
                       (r.RootIsItselfOutdated ? " ⚠" : string.Empty) +
                       (r.IsProjectReference ? " *(ProjectReference)*" : string.Empty) +
                       (r.AutoReferenced ? " *(autoReferenced)*" : string.Empty);
            sb.AppendLine($"| {r.Order} | {name} | `{r.RootVersion}` | {r.Covers.Count} | {r.CoversExclusively.Count} | {advice} |");
        }

        sb.AppendLine();
        sb.AppendLine("Сортировка — по влиянию: сверху те, у кого больше «эксклюзивных» находок (гарантированный " +
                      "выигрыш от обновления). ⚠ — пакет сам отдаёт устаревший ассет. После каждого обновления " +
                      "перезапускайте `dotnet restore` и прогоняйте анализ снова.");
        sb.AppendLine();
    }

    private static void RenderFindings(StringBuilder sb, FrameworkAnalysis fw)
    {
        foreach (var severity in new[] { Severity.Error, Severity.Warning, Severity.Info })
        {
            var group = fw.Findings.Where(f => f.Severity == severity).ToList();
            if (group.Count == 0) continue;

            var title = severity switch
            {
                Severity.Error => "Ошибки",
                Severity.Warning => "Предупреждения",
                _ => "Информация",
            };

            sb.AppendLine($"#### {title} ({group.Count})");
            sb.AppendLine();

            var collapse = severity == Severity.Info && group.Count > 15;
            if (collapse)
            {
                sb.AppendLine("<details><summary>Развернуть</summary>");
                sb.AppendLine();
            }

            foreach (var f in group)
                RenderFinding(sb, f);

            if (collapse)
            {
                sb.AppendLine("</details>");
                sb.AppendLine();
            }
        }
    }

    private static void RenderFinding(StringBuilder sb, Finding f)
    {
        var marker = f.Severity switch
        {
            Severity.Error => "✖",
            Severity.Warning => "▲",
            _ => "·",
        };

        sb.AppendLine($"##### {marker} `{f.PackageId}` {f.PackageVersion} → ассет `{f.WorstAssetTfm.ShortName}`" +
                      (f.IsDirect ? " *(прямая зависимость)*" : string.Empty));
        sb.AppendLine();
        sb.AppendLine(f.Explanation);
        sb.AppendLine();

        if (f.Evidence.Count > 0)
        {
            var shown = f.Evidence.Take(5).Select(x => $"`{x.Group}` → `{x.Path}`");
            sb.AppendLine("* Ассеты: " + string.Join(", ", shown) +
                          (f.Evidence.Count > 5 ? $" (+{f.Evidence.Count - 5})" : string.Empty));
        }

        if (!f.IsDirect && f.ReachedFromRoots.Count > 0)
        {
            var label = f.ReachedFromRoots.Count == 1
                ? "Притащила прямая зависимость"
                : "Чтобы убрать, надо обновить все прямые зависимости";
            sb.AppendLine($"* Глубина в графе: {f.Depth}. {label}: " +
                          string.Join(", ", f.ReachedFromRoots.Select(r => $"`{r}`")));
        }

        foreach (var chain in f.Chains)
            sb.AppendLine($"* Путь: {chain.Render(" → ")}");

        if (f.Redundancy is not null)
            sb.AppendLine($"* 💡 {f.Redundancy.Note}");

        if (f.Upgrade is not null && f.Upgrade.Outcome != UpgradeOutcome.NotChecked)
            sb.AppendLine($"* 📦 Фид: {f.Upgrade.Render()}");

        sb.AppendLine();
    }

    private static string EscapeCell(string text) => text.Replace("|", "\\|");
}
