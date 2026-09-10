using System.Globalization;
using System.Text.RegularExpressions;

namespace TfmAudit.Model;

/// <summary>Семейство таргет-фреймворка. Сравнивать версии осмысленно только внутри одного семейства.</summary>
public enum TfmFamily
{
    Unknown = 0,

    /// <summary>.NET Core / .NET 5+ (netcoreappX.Y, netX.Y при X >= 5).</summary>
    NetCoreApp,

    /// <summary>.NET Standard (netstandardX.Y).</summary>
    NetStandard,

    /// <summary>.NET Framework (net20 … net481).</summary>
    NetFramework,

    /// <summary>Портируемые профили (portable-net45+win8 и т.п.).</summary>
    PortableProfile,

    /// <summary>Платформенные и прочие мониторы: uap, monoandroid, xamarin.ios, sl5, wp8, tizen, native, any…</summary>
    Other,

    /// <summary>Ассет без привязки к фреймворку (analyzers/, tools/, «any», «_._»).</summary>
    Agnostic,
}

/// <summary>
/// Разобранный Target Framework Moniker. Умеет читать короткие имена папок NuGet
/// (<c>net6.0</c>, <c>netcoreapp3.1</c>, <c>netstandard2.0</c>, <c>net48</c>,
/// <c>net8.0-windows7.0</c>) и алиасы таргетов из project.assets.json (<c>net8.0/win-x64</c>).
/// </summary>
public sealed class Tfm : IEquatable<Tfm>
{
    private static readonly Regex NetCoreAppDotted =
        new(@"^net(?<maj>\d+)\.(?<min>\d+)(?<rev>\.\d+)?(?:-(?<plat>[a-z]+)(?<platver>[\d.]+)?)?$", RegexOptions.Compiled);

    private static readonly Regex NetCoreAppLegacy =
        new(@"^netcoreapp(?<maj>\d+)\.(?<min>\d+)$", RegexOptions.Compiled);

    private static readonly Regex NetStandardRe =
        new(@"^netstandard(?<maj>\d+)\.(?<min>\d+)$", RegexOptions.Compiled);

    private static readonly Regex NetFrameworkRe =
        new(@"^net(?<digits>\d{2,3})(?:-(?:client|full))?$", RegexOptions.Compiled);

    private static readonly Regex OtherRe =
        new(@"^(?:uap|monoandroid|monotouch|monomac|xamarin|sl\d|wp\d|wpa|win\d*|netmf|tizen|netcore\d|dnxcore|dnx|aspnetcore\d|aspnet\d|dotnet\d*)", RegexOptions.Compiled);

    private Tfm(string raw, TfmFamily family, Version version, string? platform, Version? platformVersion)
    {
        Raw = raw;
        Family = family;
        Version = version;
        Platform = platform;
        PlatformVersion = platformVersion;
    }

    /// <summary>Строка как она была записана в assets-файле.</summary>
    public string Raw { get; }

    public TfmFamily Family { get; }

    /// <summary>Версия внутри семейства. Для <see cref="TfmFamily.Agnostic"/> и <see cref="TfmFamily.Other"/> — 0.0.</summary>
    public Version Version { get; }

    /// <summary>Платформа из TFM вида net8.0-windows → «windows».</summary>
    public string? Platform { get; }

    public Version? PlatformVersion { get; }

    /// <summary>Ассет без TFM: analyzers, tools, «any».</summary>
    public bool IsAgnostic => Family == TfmFamily.Agnostic;

    /// <summary>Каноническое короткое имя (то, как называется папка в пакете).</summary>
    public string ShortName
    {
        get
        {
            switch (Family)
            {
                case TfmFamily.NetCoreApp:
                    var core = Version.Major >= 5
                        ? $"net{Version.Major}.{Version.Minor}"
                        : $"netcoreapp{Version.Major}.{Version.Minor}";
                    return Platform is null ? core : $"{core}-{Platform}";
                case TfmFamily.NetStandard:
                    return $"netstandard{Version.Major}.{Version.Minor}";
                case TfmFamily.NetFramework:
                    var digits = Version.Build > 0
                        ? $"{Version.Major}{Version.Minor}{Version.Build}"
                        : $"{Version.Major}{Version.Minor}";
                    return $"net{digits}";
                default:
                    return Raw;
            }
        }
    }

    /// <summary>Человекочитаемое имя для отчёта.</summary>
    public string DisplayName
    {
        get
        {
            switch (Family)
            {
                case TfmFamily.NetCoreApp:
                    var name = Version.Major >= 5
                        ? $".NET {Version.Major}.{Version.Minor}"
                        : $".NET Core {Version.Major}.{Version.Minor}";
                    return Platform is null ? name : $"{name} ({Platform})";
                case TfmFamily.NetStandard:
                    return $".NET Standard {Version.Major}.{Version.Minor}";
                case TfmFamily.NetFramework:
                    return Version.Build > 0
                        ? $".NET Framework {Version.Major}.{Version.Minor}.{Version.Build}"
                        : $".NET Framework {Version.Major}.{Version.Minor}";
                case TfmFamily.PortableProfile:
                    return $"Portable-профиль ({Raw})";
                case TfmFamily.Agnostic:
                    return "без привязки к фреймворку";
                default:
                    return Raw;
            }
        }
    }

    /// <summary>Разбор TFM. Никогда не бросает исключение: неизвестное превращается в <see cref="TfmFamily.Unknown"/>.</summary>
    public static Tfm Parse(string value)
    {
        var raw = (value ?? string.Empty).Trim();

        // Алиас таргета в assets-файле может быть с RID: "net8.0/win-x64".
        var slash = raw.IndexOf('/');
        var head = slash >= 0 ? raw.Substring(0, slash) : raw;

        var s = head.Trim().ToLowerInvariant();

        if (s.Length == 0 || s == "_._" || s == "any" || s == "agnostic" || s == "dotnet")
            return new Tfm(raw, TfmFamily.Agnostic, new Version(0, 0), null, null);

        var m = NetCoreAppDotted.Match(s);
        if (m.Success)
        {
            var ver = MakeVersion(m.Groups["maj"].Value, m.Groups["min"].Value, m.Groups["rev"].Value);
            // net1.0 … net4.8 в точечной записи — это .NET Framework, а не .NET Core.
            var family = ver.Major >= 5 ? TfmFamily.NetCoreApp : TfmFamily.NetFramework;
            Version? platVer = null;
            if (m.Groups["platver"].Success && m.Groups["platver"].Value.Length > 0)
                Version.TryParse(NormalizeVersionText(m.Groups["platver"].Value), out platVer);
            var plat = m.Groups["plat"].Success && m.Groups["plat"].Value.Length > 0 ? m.Groups["plat"].Value : null;
            return new Tfm(raw, family, ver, plat, platVer);
        }

        m = NetCoreAppLegacy.Match(s);
        if (m.Success)
            return new Tfm(raw, TfmFamily.NetCoreApp, MakeVersion(m.Groups["maj"].Value, m.Groups["min"].Value, null), null, null);

        m = NetStandardRe.Match(s);
        if (m.Success)
            return new Tfm(raw, TfmFamily.NetStandard, MakeVersion(m.Groups["maj"].Value, m.Groups["min"].Value, null), null, null);

        m = NetFrameworkRe.Match(s);
        if (m.Success)
        {
            var d = m.Groups["digits"].Value;
            var major = int.Parse(d.Substring(0, 1), CultureInfo.InvariantCulture);
            var minor = int.Parse(d.Substring(1, 1), CultureInfo.InvariantCulture);
            var build = d.Length > 2 ? int.Parse(d.Substring(2, 1), CultureInfo.InvariantCulture) : 0;
            return new Tfm(raw, TfmFamily.NetFramework, new Version(major, minor, build), null, null);
        }

        if (s.StartsWith("portable-", StringComparison.Ordinal) || s.StartsWith(".netportable", StringComparison.Ordinal))
            return new Tfm(raw, TfmFamily.PortableProfile, new Version(0, 0), null, null);

        if (OtherRe.IsMatch(s) || s == "native")
            return new Tfm(raw, TfmFamily.Other, new Version(0, 0), null, null);

        return new Tfm(raw, TfmFamily.Unknown, new Version(0, 0), null, null);
    }

    private static string NormalizeVersionText(string text)
    {
        var t = text.Trim('.');
        return t.Contains('.') ? t : t + ".0";
    }

    private static Version MakeVersion(string maj, string min, string? rev)
    {
        var major = int.Parse(maj, CultureInfo.InvariantCulture);
        var minor = int.Parse(min, CultureInfo.InvariantCulture);
        var build = 0;
        if (!string.IsNullOrEmpty(rev))
            int.TryParse(rev!.TrimStart('.'), NumberStyles.Integer, CultureInfo.InvariantCulture, out build);
        return new Version(major, minor, build);
    }

    /// <summary>
    /// Насколько ассет «моложе» цели, в мажорных поколениях. Определено только внутри одного семейства.
    /// Положительное число — ассет отстаёт.
    /// </summary>
    public int MajorGenerationsBehind(Tfm target)
    {
        if (Family != target.Family) return 0;
        return target.Version.Major - Version.Major;
    }

    public bool Equals(Tfm? other) =>
        other is not null && Family == other.Family && Version == other.Version &&
        string.Equals(Platform, other.Platform, StringComparison.OrdinalIgnoreCase);

    public override bool Equals(object? obj) => Equals(obj as Tfm);

    public override int GetHashCode() =>
        HashCode.Combine((int)Family, Version, Platform?.ToLowerInvariant());

    public override string ToString() => ShortName;
}
