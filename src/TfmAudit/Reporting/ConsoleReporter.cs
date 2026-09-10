using System.Text;
using TfmAudit.Analysis;

namespace TfmAudit.Reporting;

/// <summary>Печатает отчёт в терминал: сводка, что обновлять, затем находки с цепочками.</summary>
public sealed class ConsoleReporter
{
    private readonly TextWriter _out;
    private readonly bool _color;

    public ConsoleReporter(TextWriter output, bool color)
    {
        _out = output;
        _color = color;
    }

    private const string Reset = "\u001b[0m";
    private const string Bold = "\u001b[1m";
    private const string Dim = "\u001b[2m";
    private const string Red = "\u001b[31m";
    private const string Yellow = "\u001b[33m";
    private const string Blue = "\u001b[36m";
    private const string Green = "\u001b[32m";
    private const string Magenta = "\u001b[35m";

    private string C(string code, string text) => _color ? code + text + Reset : text;

    public void Write(AuditReport report)
    {
        _out.WriteLine();
        _out.WriteLine(C(Bold, "══ tfm-audit " + report.ToolVersion + " ══ ") +
                       C(Dim, report.GeneratedAt.ToString("dd.MM.yyyy HH:mm")));
        _out.WriteLine();
        _out.WriteLine("Ищем пакеты, которые под данным таргетом отдают ассеты более раннего поколения");
        _out.WriteLine("(например lib/net6.0 под net8.0). Каждый таргет проверяется относительно себя,");
        _out.WriteLine("поэтому мультитаргетность и условные ссылки в csproj находками не считаются.");

        if (report.OnlineMode)
        {
            _out.WriteLine();
            _out.WriteLine(C(Dim, "Источники NuGet: " + (report.Sources.Count > 0 ? string.Join(", ", report.Sources) : "нет")));
        }

        foreach (var note in report.Notes)
            _out.WriteLine(C(Yellow, "  ! " + note));

        foreach (var project in report.Projects)
            WriteProject(project);

        WriteTotals(report);
    }

    private void WriteProject(ProjectAnalysis project)
    {
        _out.WriteLine();
        _out.WriteLine(C(Bold, "Проект: " + project.Name));
        _out.WriteLine(C(Dim, "  assets:  " + project.AssetsPath));
        if (project.ProjectPath is not null) _out.WriteLine(C(Dim, "  csproj:  " + project.ProjectPath));
        _out.WriteLine(C(Dim, "  таргеты: " + string.Join(", ", project.Frameworks.Select(f => f.Alias))));

        foreach (var fw in project.Frameworks)
            WriteFramework(fw);
    }

    private void WriteFramework(FrameworkAnalysis fw)
    {
        _out.WriteLine();
        _out.WriteLine(C(Bold, new string('─', 78)));
        _out.WriteLine(C(Bold, $" Таргет {fw.Alias}  ({fw.Tfm.DisplayName})"));
        _out.WriteLine(C(Bold, new string('─', 78)));

        var errors = fw.Findings.Count(f => f.Severity == Severity.Error);
        var warnings = fw.Findings.Count(f => f.Severity == Severity.Warning);
        var infos = fw.Findings.Count(f => f.Severity == Severity.Info);

        _out.WriteLine($"  Пакетов в графе:          {fw.PackageCount}" +
                       (fw.ProjectReferenceCount > 0 ? $" (+{fw.ProjectReferenceCount} project-ссылок)" : string.Empty));
        _out.WriteLine($"  Прямых зависимостей:      {fw.DirectDependencies.Count}");
        _out.WriteLine($"  Ассет ровно под таргет:   {fw.UpToDateCount}");
        _out.WriteLine($"  Без TFM-ассетов:          {fw.AssetlessCount}   " + C(Dim, "(аналайзеры, метапакеты, контент)"));
        _out.WriteLine($"  Находки:                  " +
                       C(errors > 0 ? Red : Dim, $"{errors} ошиб.") + "  " +
                       C(warnings > 0 ? Yellow : Dim, $"{warnings} предупр.") + "  " +
                       C(Dim, $"{infos} инф."));

        if (fw.AssetTargetFallback)
        {
            _out.WriteLine();
            _out.WriteLine(C(Yellow, "  ! Для этого таргета включён AssetTargetFallback" +
                                     (fw.Imports.Count > 0 ? $" ({string.Join(", ", fw.Imports)})" : string.Empty) + "."));
            _out.WriteLine(C(Yellow, "    Это значит, что несовместимые ассеты подставляются молча, без ошибки восстановления."));
        }

        WriteHistogram(fw);

        if (fw.Findings.Count == 0)
        {
            _out.WriteLine();
            _out.WriteLine(C(Green, "  ✔ Устаревших ассетов под этот таргет не найдено."));
            return;
        }

        WriteRecommendations(fw);
        WriteFindings(fw);
    }

    private void WriteHistogram(FrameworkAnalysis fw)
    {
        if (fw.AssetTfmHistogram.Count == 0) return;

        _out.WriteLine();
        _out.WriteLine("  Худший TFM выбранных ассетов, по пакетам:");

        var items = fw.AssetTfmHistogram.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).ToList();
        var max = items.Max(kv => kv.Value);
        var width = Math.Max(4, items.Max(kv => kv.Key.Length));

        foreach (var kv in items)
        {
            var bars = max == 0 ? 0 : (int)Math.Round(kv.Value * 32.0 / max);
            var isTarget = kv.Key.Equals(fw.Tfm.ShortName, StringComparison.OrdinalIgnoreCase);
            var bar = new string('█', Math.Max(kv.Value > 0 ? 1 : 0, bars));
            var line = $"    {kv.Key.PadRight(width)}  {kv.Value,4}  {bar}";
            _out.WriteLine(isTarget ? C(Green, line) : kv.Key == "—" ? C(Dim, line) : line);
        }
    }

    private void WriteRecommendations(FrameworkAnalysis fw)
    {
        var plan = fw.Recommendations;
        if (plan.Count == 0) return;

        _out.WriteLine();
        _out.WriteLine(C(Bold + Blue, "  ЧТО ОБНОВИТЬ"));
        _out.WriteLine($"  К находкам ведут {Ru.Dependencies(plan.Count)} из csproj. " +
                       "Транзитивную версию напрямую не поднять —");
        _out.WriteLine("  обновлять надо тот пакет, который её тянет.");
        _out.WriteLine();
        _out.WriteLine($"  · находок, достижимых ровно из одной прямой зависимости: " +
                       C(Bold, fw.FindingsWithSingleOwner.ToString()) + " — их снимет одно обновление;");
        _out.WriteLine($"  · находок, достижимых сразу из нескольких: " +
                       C(Bold, fw.FindingsWithManyOwners.ToString()) + " — уйдут только после обновления");
        _out.WriteLine("    всех перечисленных для них виновников.");
        _out.WriteLine();
        _out.WriteLine(C(Dim, "  Список отсортирован по влиянию: сверху те, у кого больше «эксклюзивных» находок."));
        _out.WriteLine(C(Dim, "  После каждого обновления перезапускайте restore и прогоняйте анализ снова."));
        _out.WriteLine();

        foreach (var r in plan)
        {
            var head = $"  {r.Order,2}. {r.RootId} {r.RootVersion}" +
                       (r.IsProjectReference ? "   [ProjectReference]" : string.Empty);
            _out.WriteLine(C(Bold, head));

            var detail = new StringBuilder("      затрагивает ");
            detail.Append(Ru.FindingsAccusative(r.Covers.Count));
            if (r.CoversExclusively.Count == r.Covers.Count)
                detail.Append(r.Covers.Count == 1 ? " — только через него" : " — все только через него");
            else if (r.CoversExclusively.Count > 0)
                detail.Append($", из них {r.CoversExclusively.Count} только через него");
            if (r.RootIsItselfOutdated)
                detail.Append("; сам отдаёт устаревший ассет");
            if (r.AutoReferenced)
                detail.Append("; подключён SDK автоматически (autoReferenced)");
            _out.WriteLine(detail.ToString());

            if (r.RequestedRange is not null)
                _out.WriteLine(C(Dim, $"      в csproj запрошено: {r.RequestedRange}"));

            if (r.Upgrade is not null && r.Upgrade.Outcome != UpgradeOutcome.NotChecked)
                _out.WriteLine("      " + C(Magenta, "фид: " + r.Upgrade.Render()));

            if (r.CoversExclusively.Count > 0)
            {
                var shown = r.CoversExclusively.Take(8).ToList();
                _out.WriteLine(C(Dim, "      только он тянет: " + string.Join(", ", shown) +
                                     (r.CoversExclusively.Count > shown.Count
                                         ? $" и ещё {r.CoversExclusively.Count - shown.Count}"
                                         : string.Empty)));
            }

            _out.WriteLine();
        }
    }

    private void WriteFindings(FrameworkAnalysis fw)
    {
        foreach (var severity in new[] { Severity.Error, Severity.Warning, Severity.Info })
        {
            var group = fw.Findings.Where(f => f.Severity == severity).ToList();
            if (group.Count == 0) continue;

            var (title, colour) = severity switch
            {
                Severity.Error => ("ОШИБКИ — ассет отстаёт на два и более поколения", Red),
                Severity.Warning => ("ПРЕДУПРЕЖДЕНИЯ", Yellow),
                _ => ("ИНФОРМАЦИЯ", Dim),
            };

            _out.WriteLine();
            _out.WriteLine(C(Bold + colour, $"  {title} ({group.Count})"));
            _out.WriteLine();

            foreach (var f in group)
                WriteFinding(f, colour);
        }
    }

    private void WriteFinding(Finding f, string colour)
    {
        var bullet = f.Severity switch
        {
            Severity.Error => "✖",
            Severity.Warning => "▲",
            _ => "·",
        };

        var head = $"  {bullet} {f.PackageId} {f.PackageVersion}";
        var tail = $"  →  ассет {f.WorstAssetTfm.ShortName}" +
                   (f.GenerationsBehind > 0 ? $" (отстаёт на {f.GenerationsBehind})" : string.Empty) +
                   (f.IsDirect ? "  [прямая зависимость]" : string.Empty);
        _out.WriteLine(C(colour, head) + C(Dim, tail));

        _out.WriteLine($"      {f.Explanation}");

        var evidence = f.Evidence.Take(3).Select(e => $"{e.Group}: {e.Path}").ToList();
        if (evidence.Count > 0)
        {
            _out.WriteLine(C(Dim, "      ассеты: " + string.Join("; ", evidence) +
                                 (f.Evidence.Count > evidence.Count ? $" (+{f.Evidence.Count - evidence.Count})" : string.Empty)));
        }

        if (!f.IsDirect && f.ReachedFromRoots.Count > 0)
        {
            var label = f.ReachedFromRoots.Count == 1 ? "притащил" : "чтобы убрать — обновить все";
            _out.WriteLine($"      глубина {f.Depth}, {label}: " +
                           string.Join(", ", f.ReachedFromRoots.Take(6)) +
                           (f.ReachedFromRoots.Count > 6 ? $" и ещё {f.ReachedFromRoots.Count - 6}" : string.Empty));
        }

        foreach (var chain in f.Chains)
            _out.WriteLine(C(Dim, "      путь: ") + chain.Render());

        if (f.Redundancy is not null)
            _out.WriteLine("      " + C(Blue, "подсказка: " + f.Redundancy.Note));

        if (f.Upgrade is not null && f.Upgrade.Outcome != UpgradeOutcome.NotChecked)
            _out.WriteLine("      " + C(Magenta, "фид: " + f.Upgrade.Render()));

        _out.WriteLine();
    }

    private void WriteTotals(AuditReport report)
    {
        _out.WriteLine(C(Bold, new string('═', 78)));
        var e = report.Projects.SelectMany(p => p.Frameworks).SelectMany(f => f.Findings).Count(f => f.Severity == Severity.Error);
        var w = report.Projects.SelectMany(p => p.Frameworks).SelectMany(f => f.Findings).Count(f => f.Severity == Severity.Warning);
        var i = report.Projects.SelectMany(p => p.Frameworks).SelectMany(f => f.Findings).Count(f => f.Severity == Severity.Info);

        if (e + w + i == 0)
        {
            _out.WriteLine(C(Green, " Итого: устаревших ассетов не найдено."));
            return;
        }

        _out.WriteLine($" Итого по всем проектам и таргетам: " +
                       C(e > 0 ? Red : Dim, $"{e} ошиб.") + "  " +
                       C(w > 0 ? Yellow : Dim, $"{w} предупр.") + "  " +
                       C(Dim, $"{i} инф."));
        _out.WriteLine(C(Bold, new string('═', 78)));
    }
}
