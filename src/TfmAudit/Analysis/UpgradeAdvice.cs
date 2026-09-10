namespace TfmAudit.Analysis;

public enum UpgradeOutcome
{
    /// <summary>Фид не опрашивался.</summary>
    NotChecked = 0,

    /// <summary>Найдена версия, которая уже отдаёт ассет под целевой TFM.</summary>
    UpgradeAvailable,

    /// <summary>Текущая версия и так поддерживает таргет — ассет старый по другой причине (например, у пакета просто нет папки под новый TFM).</summary>
    AlreadySupported,

    /// <summary>Ни одна доступная версия не поддерживает целевой TFM: пакет заброшен, нужна замена.</summary>
    NoSupportingVersion,

    /// <summary>Пакета нет в настроенных фидах (внутренний пакет, недоступный источник).</summary>
    PackageNotFound,

    /// <summary>Опрос не удался (сеть, авторизация, таймаут).</summary>
    Failed,
}

/// <summary>Совет по обновлению пакета, полученный из NuGet-фида.</summary>
public sealed class UpgradeAdvice
{
    public UpgradeAdvice(string packageId, string currentVersion, UpgradeOutcome outcome)
    {
        PackageId = packageId;
        CurrentVersion = currentVersion;
        Outcome = outcome;
    }

    public string PackageId { get; }

    public string CurrentVersion { get; }

    public UpgradeOutcome Outcome { get; }

    /// <summary>Минимальная версия, у которой есть ассет под целевой TFM.</summary>
    public string? MinimumSupportingVersion { get; set; }

    /// <summary>Последняя стабильная версия в фиде.</summary>
    public string? LatestStableVersion { get; set; }

    /// <summary>Последняя версия вообще, включая pre-release.</summary>
    public string? LatestVersion { get; set; }

    /// <summary>TFM-ы, обнаруженные у предлагаемой версии.</summary>
    public List<string> SupportedTfms { get; } = new();

    /// <summary>Источник, из которого получен ответ.</summary>
    public string? Source { get; set; }

    /// <summary>Как определяли поддержку TFM: «nuspec» или «содержимое пакета».</summary>
    public string? DetectionMethod { get; set; }

    public string? Message { get; set; }

    /// <summary>
    /// Ассет ровно под целевой TFM для этого пакета не обязателен: текущий ассет формально
    /// совместим (.NET Standard). Тогда отсутствие net-версии — не приговор.
    /// </summary>
    public bool TargetAssetOptional { get; set; }

    public string Render() => Outcome switch
    {
        UpgradeOutcome.UpgradeAvailable =>
            $"обновить до {MinimumSupportingVersion}" +
            (LatestStableVersion is not null && LatestStableVersion != MinimumSupportingVersion
                ? $" (минимальная версия с нужным ассетом; последняя стабильная — {LatestStableVersion})"
                : " (минимальная версия с нужным ассетом)"),
        UpgradeOutcome.AlreadySupported =>
            $"версия {CurrentVersion} уже заявляет нужный таргет — старый ассет выбран не из-за версии пакета",
        UpgradeOutcome.NoSupportingVersion when TargetAssetOptional =>
            "пакет не публикует ассет под целевой таргет (собирается под .NET Standard). Это рабочая ситуация, " +
            "но обновление до последней версии всё равно может убрать старые транзитивные зависимости" +
            (LatestStableVersion is not null ? $"; последняя стабильная — {LatestStableVersion}" : string.Empty),
        UpgradeOutcome.NoSupportingVersion =>
            "ни одна версия в фиде не отдаёт ассет под целевой таргет — скорее всего пакет заброшен и нужна замена" +
            (LatestVersion is not null ? $" (последняя в фиде — {LatestVersion})" : string.Empty),
        UpgradeOutcome.PackageNotFound => "пакет не найден в настроенных источниках",
        UpgradeOutcome.Failed => $"опрос фида не удался: {Message}",
        _ => "фид не опрашивался",
    };
}
