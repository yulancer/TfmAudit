using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace TfmAudit.NuGet;

/// <summary>Что известно про TFM-ы конкретной версии пакета.</summary>
public sealed class PackageTfmInfo
{
    public PackageTfmInfo(string method)
    {
        DetectionMethod = method;
    }

    /// <summary>Короткие имена TFM: из nuspec-групп зависимостей или из папок lib/ref в пакете.</summary>
    public HashSet<string> Tfms { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>«nuspec» или «содержимое пакета».</summary>
    public string DetectionMethod { get; }

    public bool IsEmpty => Tfms.Count == 0;
}

/// <summary>Один настроенный источник NuGet с разрешёнными ресурсами V3.</summary>
public sealed class ResolvedSource
{
    public ResolvedSource(PackageSource source)
    {
        Source = source;
    }

    public PackageSource Source { get; }

    public string? PackageBaseAddress { get; set; }

    public string? Error { get; set; }

    public bool IsUsable => PackageBaseAddress is not null;
}

/// <summary>
/// Тонкий клиент NuGet V3 поверх HttpClient. Никаких пакетов NuGet.* не требуется:
/// используются только service index, flat container (PackageBaseAddress) и, при --deep,
/// чтение папок lib/ref прямо из .nupkg.
/// </summary>
public sealed class NuGetFeedClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly List<ResolvedSource> _sources = new();
    private readonly Dictionary<string, IReadOnlyList<NuGetVersion>> _versionCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PackageTfmInfo?> _tfmCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ResolvedSource> _sourceOfPackage = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _throttle;
    private readonly TextWriter? _log;
    private readonly long _maxNupkgBytes;

    public NuGetFeedClient(IEnumerable<PackageSource> sources, TimeSpan timeout, int maxParallel, long maxNupkgBytes, TextWriter? log)
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        };

        _http = new HttpClient(handler) { Timeout = timeout };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("tfm-audit", "1.0"));
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        _throttle = new SemaphoreSlim(Math.Max(1, maxParallel));
        _log = log;
        _maxNupkgBytes = maxNupkgBytes;

        foreach (var s in sources) _sources.Add(new ResolvedSource(s));
    }

    public IReadOnlyList<ResolvedSource> Sources => _sources;

    /// <summary>Разрешает service index каждого источника. Возвращает число пригодных источников.</summary>
    public async Task<int> InitializeAsync(CancellationToken ct)
    {
        foreach (var resolved in _sources)
        {
            var url = resolved.Source.Url;

            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                resolved.Error = "локальная папка-источник не поддерживается";
                continue;
            }

            if (!url.EndsWith("index.json", StringComparison.OrdinalIgnoreCase))
            {
                resolved.Error = "источник не в формате NuGet V3 (ожидался URL, оканчивающийся на index.json)";
                continue;
            }

            try
            {
                var json = await GetStringAsync(url, resolved.Source, ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("resources", out var resources) || resources.ValueKind != JsonValueKind.Array)
                {
                    resolved.Error = "в service index нет секции resources";
                    continue;
                }

                foreach (var res in resources.EnumerateArray())
                {
                    var type = res.TryGetProperty("@type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
                    var id = res.TryGetProperty("@id", out var i) && i.ValueKind == JsonValueKind.String ? i.GetString() : null;
                    if (type is null || id is null) continue;

                    if (type.StartsWith("PackageBaseAddress/3.0.0", StringComparison.OrdinalIgnoreCase))
                        resolved.PackageBaseAddress = id.TrimEnd('/') + "/";
                }

                if (resolved.PackageBaseAddress is null)
                    resolved.Error = "источник не публикует ресурс PackageBaseAddress/3.0.0";
            }
            catch (Exception ex)
            {
                resolved.Error = Describe(ex);
            }
        }

        return _sources.Count(s => s.IsUsable);
    }

    /// <summary>Все версии пакета, объединённые по всем пригодным источникам, по возрастанию.</summary>
    public async Task<IReadOnlyList<NuGetVersion>> GetVersionsAsync(string packageId, CancellationToken ct)
    {
        lock (_versionCache)
        {
            if (_versionCache.TryGetValue(packageId, out var cached)) return cached;
        }

        var all = new List<NuGetVersion>();
        var lower = packageId.ToLowerInvariant();

        foreach (var source in _sources.Where(s => s.IsUsable))
        {
            var url = $"{source.PackageBaseAddress}{Uri.EscapeDataString(lower)}/index.json";
            try
            {
                var json = await GetStringAsync(url, source.Source, ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("versions", out var versions) || versions.ValueKind != JsonValueKind.Array)
                    continue;

                var found = false;
                foreach (var v in versions.EnumerateArray())
                {
                    if (v.ValueKind != JsonValueKind.String) continue;
                    if (NuGetVersion.TryParse(v.GetString(), out var parsed))
                    {
                        all.Add(parsed);
                        found = true;
                    }
                }

                if (found)
                {
                    lock (_sourceOfPackage) _sourceOfPackage[packageId] = source;
                }
            }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
            {
                // Пакета нет в этом источнике — нормально.
            }
            catch (Exception ex)
            {
                _log?.WriteLine($"  ! {packageId}: {source.Source.Name}: {Describe(ex)}");
            }
        }

        var ordered = all
            .GroupBy(v => v.Original, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(v => v)
            .ToList();

        lock (_versionCache) _versionCache[packageId] = ordered;
        return ordered;
    }

    public string? SourceNameFor(string packageId)
    {
        lock (_sourceOfPackage)
            return _sourceOfPackage.TryGetValue(packageId, out var s) ? s.Source.Name : null;
    }

    /// <summary>TFM-ы конкретной версии: сначала из nuspec, при deep — из папок lib/ref внутри .nupkg.</summary>
    public async Task<PackageTfmInfo?> GetTfmsAsync(string packageId, NuGetVersion version, bool deep, CancellationToken ct)
    {
        var cacheKey = $"{packageId}/{version.Original}/{(deep ? "deep" : "nuspec")}";
        lock (_tfmCache)
        {
            if (_tfmCache.TryGetValue(cacheKey, out var cached)) return cached;
        }

        PackageTfmInfo? info = null;

        if (deep)
        {
            info = await ReadTfmsFromNupkgAsync(packageId, version, ct).ConfigureAwait(false);
        }

        if (info is null || info.IsEmpty)
        {
            var fromNuspec = await ReadTfmsFromNuspecAsync(packageId, version, ct).ConfigureAwait(false);
            if (fromNuspec is not null && !fromNuspec.IsEmpty) info = fromNuspec;
            else info ??= fromNuspec;
        }

        lock (_tfmCache) _tfmCache[cacheKey] = info;
        return info;
    }

    private async Task<PackageTfmInfo?> ReadTfmsFromNuspecAsync(string packageId, NuGetVersion version, CancellationToken ct)
    {
        var lowerId = packageId.ToLowerInvariant();
        var lowerVer = version.Original.ToLowerInvariant();

        foreach (var source in UsableSourcesFor(packageId))
        {
            var url = $"{source.PackageBaseAddress}{Uri.EscapeDataString(lowerId)}/{Uri.EscapeDataString(lowerVer)}/{Uri.EscapeDataString(lowerId)}.nuspec";
            try
            {
                var xml = await GetStringAsync(url, source.Source, ct).ConfigureAwait(false);
                var doc = XDocument.Parse(xml);
                var info = new PackageTfmInfo("nuspec");

                foreach (var group in doc.Descendants().Where(e => e.Name.LocalName == "group"))
                {
                    var tfm = group.Attribute("targetFramework")?.Value;
                    if (!string.IsNullOrWhiteSpace(tfm))
                        info.Tfms.Add(Model.Tfm.Parse(NormalizeNuspecTfm(tfm!)).ShortName);
                }

                return info;
            }
            catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
            {
            }
            catch (Exception ex)
            {
                _log?.WriteLine($"  ! {packageId} {version}: nuspec: {Describe(ex)}");
            }
        }

        return null;
    }

    private async Task<PackageTfmInfo?> ReadTfmsFromNupkgAsync(string packageId, NuGetVersion version, CancellationToken ct)
    {
        var lowerId = packageId.ToLowerInvariant();
        var lowerVer = version.Original.ToLowerInvariant();

        foreach (var source in UsableSourcesFor(packageId))
        {
            var url = $"{source.PackageBaseAddress}{Uri.EscapeDataString(lowerId)}/{Uri.EscapeDataString(lowerVer)}/{Uri.EscapeDataString(lowerId)}.{Uri.EscapeDataString(lowerVer)}.nupkg";
            await _throttle.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                ApplyAuth(request, source.Source);
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.NotFound) continue;
                response.EnsureSuccessStatusCode();

                if (response.Content.Headers.ContentLength is long len && len > _maxNupkgBytes)
                {
                    _log?.WriteLine($"  · {packageId} {version}: пакет {len / 1024 / 1024} МБ больше лимита — читаю nuspec вместо содержимого");
                    return null;
                }

                using var buffer = new MemoryStream();
                using (var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                {
                    var chunk = new byte[81920];
                    int read;
                    while ((read = await stream.ReadAsync(chunk, 0, chunk.Length, ct).ConfigureAwait(false)) > 0)
                    {
                        buffer.Write(chunk, 0, read);
                        if (buffer.Length > _maxNupkgBytes) return null;
                    }
                }

                buffer.Position = 0;
                using var zip = new ZipArchive(buffer, ZipArchiveMode.Read);
                var info = new PackageTfmInfo("содержимое пакета");
                foreach (var entry in zip.Entries)
                {
                    var parsed = Analysis.AssetPathParser.Parse("compile", entry.FullName);
                    var name = entry.FullName.Replace('\\', '/');
                    if (parsed.Tfm is null) continue;
                    if (!name.StartsWith("lib/", StringComparison.OrdinalIgnoreCase) &&
                        !name.StartsWith("ref/", StringComparison.OrdinalIgnoreCase) &&
                        !name.StartsWith("runtimes/", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    info.Tfms.Add(parsed.Tfm.ShortName);
                }

                return info;
            }
            catch (Exception ex)
            {
                _log?.WriteLine($"  ! {packageId} {version}: nupkg: {Describe(ex)}");
            }
            finally
            {
                _throttle.Release();
            }
        }

        return null;
    }

    private IEnumerable<ResolvedSource> UsableSourcesFor(string packageId)
    {
        ResolvedSource? preferred;
        lock (_sourceOfPackage) _sourceOfPackage.TryGetValue(packageId, out preferred);

        if (preferred is not null) yield return preferred;
        foreach (var s in _sources)
        {
            if (!s.IsUsable || ReferenceEquals(s, preferred)) continue;
            yield return s;
        }
    }

    /// <summary>Nuspec пишет длинные имена (".NETStandard2.0", ".NETCoreApp,Version=v8.0"). Приводим к короткому.</summary>
    internal static string NormalizeNuspecTfm(string value)
    {
        var s = value.Trim();

        if (s.StartsWith(".NETCoreApp", StringComparison.OrdinalIgnoreCase))
        {
            var v = ExtractVersion(s);
            if (v is not null) return v.Major >= 5 ? $"net{v.Major}.{v.Minor}" : $"netcoreapp{v.Major}.{v.Minor}";
        }

        if (s.StartsWith(".NETStandard", StringComparison.OrdinalIgnoreCase))
        {
            var v = ExtractVersion(s);
            if (v is not null) return $"netstandard{v.Major}.{v.Minor}";
        }

        if (s.StartsWith(".NETFramework", StringComparison.OrdinalIgnoreCase))
        {
            var v = ExtractVersion(s);
            if (v is not null)
                return v.Build > 0 ? $"net{v.Major}{v.Minor}{v.Build}" : $"net{v.Major}{v.Minor}";
        }

        return s;
    }

    private static Version? ExtractVersion(string s)
    {
        var idx = s.IndexOf("Version=v", StringComparison.OrdinalIgnoreCase);
        var text = idx >= 0
            ? s.Substring(idx + "Version=v".Length)
            : new string(s.SkipWhile(c => !char.IsDigit(c)).ToArray());

        text = text.Trim().TrimEnd(',');
        if (text.Length == 0) return null;
        if (!text.Contains('.')) text += ".0";
        return Version.TryParse(text, out var v) ? v : null;
    }

    private async Task<string> GetStringAsync(string url, PackageSource source, CancellationToken ct)
    {
        await _throttle.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Exception? last = null;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    ApplyAuth(request, source);
                    using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
                    if (response.StatusCode == HttpStatusCode.NotFound)
                        throw new HttpRequestException("404", null, HttpStatusCode.NotFound);

                    response.EnsureSuccessStatusCode();
                    return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                }
                catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    throw;
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
                {
                    last = ex;
                    await Task.Delay(TimeSpan.FromMilliseconds(250 * (attempt + 1)), ct).ConfigureAwait(false);
                }
            }

            throw last ?? new HttpRequestException($"не удалось получить {url}");
        }
        finally
        {
            _throttle.Release();
        }
    }

    private static void ApplyAuth(HttpRequestMessage request, PackageSource source)
    {
        if (string.IsNullOrEmpty(source.Username) && string.IsNullOrEmpty(source.Password)) return;
        var raw = $"{source.Username}:{source.Password}";
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", token);
    }

    private static string Describe(Exception ex) => ex switch
    {
        TaskCanceledException => "таймаут",
        HttpRequestException http when http.StatusCode is not null => $"HTTP {(int)http.StatusCode.Value}",
        _ => ex.Message,
    };

    public void Dispose()
    {
        _http.Dispose();
        _throttle.Dispose();
    }
}
