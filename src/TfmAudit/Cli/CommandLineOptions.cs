using TfmAudit.Analysis;

namespace TfmAudit.Cli;

public sealed class CommandLineOptions
{
    public List<string> Inputs { get; } = new();

    public List<string> Frameworks { get; } = new();

    public Severity MinSeverity { get; set; } = Severity.Info;

    public Severity? FailOn { get; set; }

    public bool NetStandardAsWarning { get; set; }

    public int MaxChains { get; set; } = 3;

    public List<string> IgnorePackages { get; } = new();

    public bool Recurse { get; set; }

    public string? OutDir { get; set; }

    public string? MarkdownPath { get; set; }

    public string? HtmlPath { get; set; }

    public string? JsonPath { get; set; }

    public string? DotPath { get; set; }

    public string? DgmlPath { get; set; }

    public bool Online { get; set; }

    public List<string> Sources { get; } = new();

    public string? SourceUsername { get; set; }

    public string? SourcePassword { get; set; }

    public bool IncludePrerelease { get; set; }

    public bool Deep { get; set; }

    public int TimeoutSeconds { get; set; } = 30;

    public int MaxParallel { get; set; } = 8;

    public bool NoColor { get; set; }

    public bool Quiet { get; set; }

    public bool ShowHelp { get; set; }

    public bool ShowVersion { get; set; }

    /// <summary>Ошибки разбора аргументов.</summary>
    public List<string> Errors { get; } = new();

    public bool AnyFileOutput => MarkdownPath is not null || HtmlPath is not null || JsonPath is not null ||
                                 DotPath is not null || DgmlPath is not null;

    public static CommandLineOptions Parse(string[] args)
    {
        var o = new CommandLineOptions();
        var allFormats = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            string? Value(bool optional = false)
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
                    return args[++i];

                if (!optional) o.Errors.Add($"у параметра {arg} не указано значение");
                return null;
            }

            switch (arg)
            {
                case "-h":
                case "--help":
                case "/?":
                    o.ShowHelp = true;
                    break;

                case "--version":
                    o.ShowVersion = true;
                    break;

                case "-f":
                case "--framework":
                    var fw = Value();
                    if (fw is not null) o.Frameworks.Add(fw);
                    break;

                case "--min-severity":
                    var ms = Value();
                    if (ms is not null)
                    {
                        if (SeverityText.TryParse(ms, out var parsed)) o.MinSeverity = parsed;
                        else o.Errors.Add($"неизвестный уровень: {ms} (ожидалось error|warning|info)");
                    }

                    break;

                case "--fail-on":
                    var fo = Value();
                    if (fo is not null)
                    {
                        if (fo.Equals("none", StringComparison.OrdinalIgnoreCase)) o.FailOn = null;
                        else if (SeverityText.TryParse(fo, out var parsedFail)) o.FailOn = parsedFail;
                        else o.Errors.Add($"неизвестный уровень: {fo} (ожидалось error|warning|info|none)");
                    }

                    break;

                case "--netstandard-as-warning":
                    o.NetStandardAsWarning = true;
                    break;

                case "--max-chains":
                    var mc = Value();
                    if (mc is not null)
                    {
                        if (int.TryParse(mc, out var n) && n > 0) o.MaxChains = n;
                        else o.Errors.Add($"--max-chains ожидает положительное число, получено: {mc}");
                    }

                    break;

                case "--ignore":
                    var ig = Value();
                    if (ig is not null) o.IgnorePackages.AddRange(ig.Split(';', StringSplitOptions.RemoveEmptyEntries));
                    break;

                case "-r":
                case "--recurse":
                    o.Recurse = true;
                    break;

                case "-o":
                case "--out-dir":
                    o.OutDir = Value();
                    break;

                case "--md":
                case "--markdown":
                    o.MarkdownPath = Value(optional: true) ?? string.Empty;
                    break;

                case "--html":
                    o.HtmlPath = Value(optional: true) ?? string.Empty;
                    break;

                case "--json":
                    o.JsonPath = Value(optional: true) ?? string.Empty;
                    break;

                case "--dot":
                    o.DotPath = Value(optional: true) ?? string.Empty;
                    break;

                case "--dgml":
                    o.DgmlPath = Value(optional: true) ?? string.Empty;
                    break;

                case "--all-formats":
                    allFormats = true;
                    break;

                case "--online":
                    o.Online = true;
                    break;

                case "--source":
                    var src = Value();
                    if (src is not null) o.Sources.Add(src);
                    break;

                case "--source-username":
                    o.SourceUsername = Value();
                    break;

                case "--source-password":
                    o.SourcePassword = Value();
                    break;

                case "--include-prerelease":
                    o.IncludePrerelease = true;
                    break;

                case "--deep":
                    o.Deep = true;
                    break;

                case "--timeout":
                    var to = Value();
                    if (to is not null)
                    {
                        if (int.TryParse(to, out var secs) && secs > 0) o.TimeoutSeconds = secs;
                        else o.Errors.Add($"--timeout ожидает положительное число секунд, получено: {to}");
                    }

                    break;

                case "--max-parallel":
                    var mp = Value();
                    if (mp is not null)
                    {
                        if (int.TryParse(mp, out var par) && par > 0) o.MaxParallel = par;
                        else o.Errors.Add($"--max-parallel ожидает положительное число, получено: {mp}");
                    }

                    break;

                case "--no-color":
                    o.NoColor = true;
                    break;

                case "-q":
                case "--quiet":
                    o.Quiet = true;
                    break;

                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal))
                        o.Errors.Add($"неизвестный параметр: {arg}");
                    else
                        o.Inputs.Add(arg);
                    break;
            }
        }

        if (allFormats)
        {
            o.MarkdownPath ??= string.Empty;
            o.HtmlPath ??= string.Empty;
            o.JsonPath ??= string.Empty;
            o.DotPath ??= string.Empty;
            o.DgmlPath ??= string.Empty;
        }

        if (o.Deep && !o.Online)
            o.Errors.Add("--deep имеет смысл только вместе с --online");

        if (Environment.GetEnvironmentVariable("NO_COLOR") is not null) o.NoColor = true;

        return o;
    }

    public const string HelpText = @"tfm-audit — анализатор устаревших таргетов в графе зависимостей NuGet.

Читает project.assets.json и для каждого таргета проекта находит пакеты, чьи ВЫБРАННЫЕ
ассеты относятся к более раннему поколению, чем сам таргет (например lib/net6.0 под net8.0
или lib/net8.0 под net10.0), после чего объясняет, какая прямая зависимость их притащила.

Мультитаргетность сама по себе ошибкой не считается: каждый таргет анализируется
относительно себя, расхождения между таргетами не отмечаются.

ИСПОЛЬЗОВАНИЕ
  tfm-audit <путь> [<путь> …] [параметры]

  <путь> — это:
    • project.assets.json;
    • папка проекта (будет взят obj/project.assets.json);
    • .csproj или .sln (будет взят obj/project.assets.json рядом);
    • папка решения вместе с -r — будут найдены все **/obj/project.assets.json.

ВЫБОРКА
  -f, --framework <tfm>        Анализировать только этот таргет (можно повторять).
      --min-severity <l>       Порог находок: error|warning|info. По умолчанию info.
      --netstandard-as-warning Считать ассеты netstandard2.x предупреждением, а не информацией.
      --ignore <a;b;c>         Не сообщать про эти пакеты (можно ""Prefix*"").
      --max-chains <n>         Сколько путей до корня показывать на находку (по умолчанию 3).
  -r, --recurse                Искать assets-файлы рекурсивно.

ОТЧЁТЫ
  -o, --out-dir <dir>          Куда писать файлы (по умолчанию ./tfm-audit-report).
      --md [файл]              Markdown-отчёт.
      --html [файл]            Интерактивный HTML-отчёт с графом (самодостаточный).
      --json [файл]            JSON для CI.
      --dot [файл]             Graphviz DOT.
      --dgml [файл]            DGML (открывается в Visual Studio).
      --all-formats            Все форматы сразу.

NUGET-ФИД (необязательно)
      --online                 Спросить у фида, до какой версии обновлять пакеты.
      --source <url>           Источник V3 (index.json). Можно повторять.
                               По умолчанию берутся источники из NuGet.config.
      --source-username <u>    Логин для источников, заданных через --source.
      --source-password <p>    Пароль/PAT для источников, заданных через --source.
      --include-prerelease     Рассматривать pre-release версии.
      --deep                   Читать содержимое .nupkg, а не только nuspec (точнее, медленнее).
      --timeout <сек>          Таймаут запроса (по умолчанию 30).
      --max-parallel <n>       Параллельных запросов (по умолчанию 8).

ПРОЧЕЕ
      --fail-on <l>            Вернуть код 2, если есть находки этого уровня и выше
                               (error|warning|info|none). По умолчанию none.
      --no-color               Без ANSI-цветов (то же делает переменная NO_COLOR).
  -q, --quiet                  Не печатать отчёт в консоль (только файлы).
  -h, --help                   Эта справка.
      --version                Версия утилиты.

КОДЫ ВОЗВРАТА
  0  успех
  1  ошибка выполнения (не найден файл, некорректные аргументы)
  2  найдены находки уровня --fail-on и выше

ПРИМЕРЫ
  tfm-audit ./src/MyApi/obj/project.assets.json
  tfm-audit ./src/MyApi -f net8.0 --md --html
  tfm-audit . -r --all-formats -o ./artifacts/tfm
  tfm-audit ./src/MyApi --online --deep --md
  tfm-audit ./src/MyApi --online --source https://nuget.company.local/v3/index.json \
            --source-username ci --source-password $NUGET_PAT
  tfm-audit ./src/MyApi --min-severity error --fail-on error --quiet --json
";
}
