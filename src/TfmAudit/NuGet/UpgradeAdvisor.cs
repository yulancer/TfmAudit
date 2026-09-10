using TfmAudit.Analysis;
using TfmAudit.Model;

namespace TfmAudit.NuGet;

public sealed class UpgradeAdvisorOptions
{
    public bool IncludePrerelease { get; set; }

    /// <summary>Читать содержимое .nupkg, а не только nuspec — точнее, но медленнее.</summary>
    public bool Deep { get; set; }
}

/// <summary>
/// Подбирает по фиду минимальную версию пакета, у которой уже есть ассет под целевой TFM.
/// Поиск идёт бинарно (поддержка TFM монотонна по версиям), поэтому на пакет уходит
/// порядка 2·log₂(N) запросов, а не N.
/// </summary>
public sealed class UpgradeAdvisor
{
    private readonly NuGetFeedClient _client;
    private readonly UpgradeAdvisorOptions _options;

    public UpgradeAdvisor(NuGetFeedClient client, UpgradeAdvisorOptions options)
    {
        _client = client;
        _options = options;
    }

    public async Task<UpgradeAdvice> AdviseAsync(
        string packageId,
        string currentVersion,
        Tfm targetTfm,
        bool targetAssetOptional,
        CancellationToken ct)
    {
        try
        {
            var versions = await _client.GetVersionsAsync(packageId, ct).ConfigureAwait(false);
            if (versions.Count == 0)
                return new UpgradeAdvice(packageId, currentVersion, UpgradeOutcome.PackageNotFound);

            var latest = versions[versions.Count - 1];
            var latestStable = versions.LastOrDefault(v => !v.IsPreRelease);

            NuGetVersion.TryParse(currentVersion, out var current);

            var candidates = versions
                .Where(v => _options.IncludePrerelease || !v.IsPreRelease)
                .Where(v => current is null || v.CompareTo(current) > 0)
                .ToList();

            var advice = new UpgradeAdvice(packageId, currentVersion, UpgradeOutcome.NotChecked)
            {
                LatestVersion = latest.Original,
                LatestStableVersion = latestStable?.Original,
                Source = _client.SourceNameFor(packageId),
                TargetAssetOptional = targetAssetOptional,
            };

            if (candidates.Count == 0)
            {
                // Новее ничего нет: проверим, что умеет текущая версия.
                if (current is not null)
                {
                    var info = await _client.GetTfmsAsync(packageId, current, _options.Deep, ct).ConfigureAwait(false);
                    if (info is not null) advice.SupportedTfms.AddRange(info.Tfms.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
                    advice.DetectionMethod = info?.DetectionMethod;
                    return Finish(advice, info is not null && Supports(info, targetTfm)
                        ? UpgradeOutcome.AlreadySupported
                        : UpgradeOutcome.NoSupportingVersion);
                }

                return Finish(advice, UpgradeOutcome.NoSupportingVersion);
            }

            // Представители минорных линеек: последняя версия каждой линейки.
            var reps = candidates
                .GroupBy(v => (v.Major, v.Minor))
                .Select(g => g.OrderBy(v => v).Last())
                .OrderBy(v => v)
                .ToList();

            var top = reps[reps.Count - 1];
            var topInfo = await _client.GetTfmsAsync(packageId, top, _options.Deep, ct).ConfigureAwait(false);
            if (topInfo is null)
                return Finish(advice, UpgradeOutcome.Failed, "не удалось прочитать метаданные пакета");

            advice.DetectionMethod = topInfo.DetectionMethod;

            if (!Supports(topInfo, targetTfm))
            {
                advice.SupportedTfms.AddRange(topInfo.Tfms.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
                return Finish(advice, UpgradeOutcome.NoSupportingVersion);
            }

            var firstRep = await BinarySearchFirstSupportingAsync(packageId, reps, targetTfm, ct).ConfigureAwait(false);
            if (firstRep is null)
                return Finish(advice, UpgradeOutcome.Failed, "поиск по версиям не сошёлся");

            var line = candidates
                .Where(v => v.Major == firstRep.Major && v.Minor == firstRep.Minor)
                .OrderBy(v => v)
                .ToList();

            var minimal = await BinarySearchFirstSupportingAsync(packageId, line, targetTfm, ct).ConfigureAwait(false) ?? firstRep;

            var minimalInfo = await _client.GetTfmsAsync(packageId, minimal, _options.Deep, ct).ConfigureAwait(false);
            if (minimalInfo is not null)
            {
                advice.SupportedTfms.AddRange(minimalInfo.Tfms.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
                advice.DetectionMethod = minimalInfo.DetectionMethod;
            }

            advice.MinimumSupportingVersion = minimal.Original;
            return Finish(advice, UpgradeOutcome.UpgradeAvailable);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new UpgradeAdvice(packageId, currentVersion, UpgradeOutcome.Failed) { Message = ex.Message };
        }
    }

    private static UpgradeAdvice Finish(UpgradeAdvice source, UpgradeOutcome outcome, string? message = null)
    {
        var result = new UpgradeAdvice(source.PackageId, source.CurrentVersion, outcome)
        {
            MinimumSupportingVersion = source.MinimumSupportingVersion,
            LatestStableVersion = source.LatestStableVersion,
            LatestVersion = source.LatestVersion,
            Source = source.Source,
            DetectionMethod = source.DetectionMethod,
            TargetAssetOptional = source.TargetAssetOptional,
            Message = message ?? source.Message,
        };

        result.SupportedTfms.AddRange(source.SupportedTfms);
        return result;
    }

    private async Task<NuGetVersion?> BinarySearchFirstSupportingAsync(
        string packageId,
        List<NuGetVersion> ascending,
        Tfm targetTfm,
        CancellationToken ct)
    {
        if (ascending.Count == 0) return null;

        var lo = 0;
        var hi = ascending.Count - 1;

        while (lo < hi)
        {
            var mid = lo + ((hi - lo) / 2);
            var info = await _client.GetTfmsAsync(packageId, ascending[mid], _options.Deep, ct).ConfigureAwait(false);
            if (info is not null && Supports(info, targetTfm)) hi = mid;
            else lo = mid + 1;
        }

        var finalInfo = await _client.GetTfmsAsync(packageId, ascending[lo], _options.Deep, ct).ConfigureAwait(false);
        return finalInfo is not null && Supports(finalInfo, targetTfm) ? ascending[lo] : null;
    }

    /// <summary>
    /// Пакет «поддерживает» таргет, только если у него есть папка ровно под этот TFM:
    /// NuGet выбирает наибольший ассет, не превышающий таргет, поэтому папка net7.0
    /// под таргетом net8.0 находку не снимет.
    /// </summary>
    private static bool Supports(PackageTfmInfo info, Tfm target)
    {
        foreach (var name in info.Tfms)
        {
            var tfm = Tfm.Parse(name);
            if (tfm.Family != target.Family) continue;
            if (tfm.Version.Major == target.Version.Major && tfm.Version.Minor == target.Version.Minor)
                return true;
        }

        return false;
    }
}
