using System.Text;
using TfmAudit.Analysis;
using TfmAudit.Cli;
using TfmAudit.Model;
using TfmAudit.NuGet;
using TfmAudit.Reporting;

namespace TfmAudit;

public static class Program
{
    private const string Version = "1.0.0";

    public static async Task<int> Main(string[] args)
    {
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
        }
        catch (IOException)
        {
            // Переназначенный вывод без консоли — не беда.
        }

        var options = CommandLineOptions.Parse(args);

        if (options.ShowVersion)
        {
            Console.WriteLine($"tfm-audit {Version}");
            return 0;
        }

        if (options.ShowHelp || (args.Length == 0))
        {
            Console.WriteLine(CommandLineOptions.HelpText);
            return args.Length == 0 ? 1 : 0;
        }

        if (options.Errors.Count > 0)
        {
            foreach (var e in options.Errors) Console.Error.WriteLine($"tfm-audit: {e}");
            Console.Error.WriteLine("Подсказка: tfm-audit --help");
            return 1;
        }

        var problems = new List<string>();
        var assetsPaths = AssetsLocator.Resolve(options.Inputs, options.Recurse, problems);

        foreach (var p in problems) Console.Error.WriteLine($"tfm-audit: {p}");

        if (assetsPaths.Count == 0)
        {
            Console.Error.WriteLine("tfm-audit: нечего анализировать.");
            return 1;
        }

        var analyzerOptions = new AnalyzerOptions
        {
            NetStandardAsWarning = options.NetStandardAsWarning,
            MaxChainsPerFinding = options.MaxChains,
            MinSeverity = options.MinSeverity,
        };
        analyzerOptions.OnlyFrameworks.AddRange(options.Frameworks);
        analyzerOptions.IgnorePackages.AddRange(options.IgnorePackages);

        var analyzer = new TfmAnalyzer(analyzerOptions);
        var report = new AuditReport { ToolVersion = Version };
        report.Notes.AddRange(problems);

        foreach (var path in assetsPaths)
        {
            try
            {
                var assets = AssetsFileReader.Read(path);
                report.Projects.Add(analyzer.Analyze(assets));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"tfm-audit: {path}: {ex.Message}");
                report.Notes.Add($"{path}: {ex.Message}");
            }
        }

        if (report.Projects.Count == 0)
        {
            Console.Error.WriteLine("tfm-audit: ни один assets-файл не удалось разобрать.");
            return 1;
        }

        if (options.Online)
            await EnrichFromFeedAsync(report, options, assetsPaths[0]).ConfigureAwait(false);

        if (!options.Quiet)
            new ConsoleReporter(Console.Out, !options.NoColor && !Console.IsOutputRedirected).Write(report);

        WriteFiles(report, options);

        if (options.FailOn is Severity threshold && report.CountAtLeast(threshold) > 0)
            return 2;

        return 0;
    }

    // ------------------------------------------------------------------ онлайн-режим

    private static async Task EnrichFromFeedAsync(AuditReport report, CommandLineOptions options, string anyAssetsPath)
    {
        report.OnlineMode = true;

        var sources = new List<PackageSource>();
        for (var i = 0; i < options.Sources.Count; i++)
        {
            sources.Add(new PackageSource($"--source[{i + 1}]", options.Sources[i])
            {
                Username = options.SourceUsername,
                Password = options.SourcePassword,
            });
        }

        if (sources.Count == 0)
        {
            var startDir = Path.GetDirectoryName(anyAssetsPath) ?? Directory.GetCurrentDirectory();
            sources.AddRange(NuGetConfigReader.Discover(startDir, options.Quiet ? null : Console.Out));

            if (sources.Count == 0)
            {
                sources.Add(new PackageSource("nuget.org", "https://api.nuget.org/v3/index.json"));
                report.Notes.Add("NuGet.config не найден — использован nuget.org.");
            }
        }

        using var client = new NuGetFeedClient(
            sources,
            TimeSpan.FromSeconds(options.TimeoutSeconds),
            options.MaxParallel,
            64L * 1024 * 1024,
            options.Quiet ? null : Console.Out);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var usable = await client.InitializeAsync(cts.Token).ConfigureAwait(false);

        foreach (var s in client.Sources)
        {
            report.Sources.Add(s.IsUsable ? s.Source.Name : $"{s.Source.Name} — недоступен: {s.Error}");
            if (!s.IsUsable) report.Notes.Add($"Источник {s.Source.Name} ({s.Source.Url}) не используется: {s.Error}");
        }

        if (usable == 0)
        {
            report.Notes.Add("Ни один источник NuGet не доступен — отчёт построен без советов по версиям.");
            return;
        }

        var advisor = new UpgradeAdvisor(client, new UpgradeAdvisorOptions
        {
            IncludePrerelease = options.IncludePrerelease,
            Deep = options.Deep,
        });

        // Собираем уникальные пары «пакет + таргет», чтобы не спрашивать фид дважды.
        var queries = new Dictionary<string, (string PackageId, string CurrentVersion, Tfm Target, bool Optional, List<object> Consumers)>(StringComparer.OrdinalIgnoreCase);

        void Enqueue(string id, string version, Tfm target, bool optional, object consumer)
        {
            var key = $"{id}|{target.ShortName}";
            if (!queries.TryGetValue(key, out var entry))
            {
                entry = (id, version, target, optional, new List<object>());
                queries[key] = entry;
            }

            entry.Consumers.Add(consumer);
        }

        foreach (var project in report.Projects)
        {
            foreach (var fw in project.Frameworks)
            {
                foreach (var f in fw.Findings)
                {
                    var optional = f.Kind is FindingKind.NetStandardAsset;
                    Enqueue(f.PackageId, f.PackageVersion, fw.Tfm, optional, f);
                }

                // ProjectReference в фиде искать бессмысленно: это локальный проект решения.
                foreach (var r in fw.Recommendations.Where(x => !x.IsProjectReference))
                    Enqueue(r.RootId, r.RootVersion, fw.Tfm, !r.RootIsItselfOutdated, r);
            }
        }

        if (!options.Quiet)
            Console.WriteLine($"Опрашиваю NuGet: {queries.Count} пакетов…");

        var throttle = new SemaphoreSlim(Math.Max(1, options.MaxParallel));
        var tasks = queries.Values.Select(async q =>
        {
            await throttle.WaitAsync(cts.Token).ConfigureAwait(false);
            try
            {
                var advice = await advisor.AdviseAsync(q.PackageId, q.CurrentVersion, q.Target, q.Optional, cts.Token)
                    .ConfigureAwait(false);

                foreach (var consumer in q.Consumers)
                {
                    if (consumer is Finding f) f.Upgrade = advice;
                    else if (consumer is Recommendation r) r.Upgrade = advice;
                }
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                throttle.Release();
            }
        }).ToArray();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            report.Notes.Add("Опрос фида прерван — часть советов по версиям отсутствует.");
        }
    }

    // ------------------------------------------------------------------ файлы отчётов

    private static void WriteFiles(AuditReport report, CommandLineOptions options)
    {
        if (!options.AnyFileOutput) return;

        var outDir = options.OutDir ?? Path.Combine(Directory.GetCurrentDirectory(), "tfm-audit-report");
        Directory.CreateDirectory(outDir);

        Save(options.MarkdownPath, outDir, "tfm-audit.md", () => MarkdownReporter.Render(report));
        Save(options.HtmlPath, outDir, "tfm-audit.html", () => HtmlReporter.Render(report));
        Save(options.JsonPath, outDir, "tfm-audit.json", () => JsonReporter.Render(report));
        Save(options.DotPath, outDir, "tfm-audit.dot", () => DotReporter.Render(report));
        Save(options.DgmlPath, outDir, "tfm-audit.dgml", () => DgmlReporter.Render(report));
    }

    private static void Save(string? requested, string outDir, string defaultName, Func<string> build)
    {
        if (requested is null) return;

        var path = requested.Length == 0
            ? Path.Combine(outDir, defaultName)
            : Path.GetFullPath(requested);

        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(path, build(), new UTF8Encoding(false));
            Console.WriteLine($"Записан отчёт: {path}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"tfm-audit: не удалось записать {path}: {ex.Message}");
        }
    }
}
