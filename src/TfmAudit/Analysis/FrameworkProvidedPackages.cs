using TfmAudit.Model;

namespace TfmAudit.Analysis;

/// <summary>Почему пакет считается лишним на современном таргете.</summary>
public enum RedundancyKind
{
    None = 0,

    /// <summary>Старый «контрактный» пакет System.* 4.x — на .NET Core это пустой фасад.</summary>
    LegacyContract,

    /// <summary>Функциональность вошла в состав рантайма (shared framework) начиная с некоторой версии.</summary>
    InBox,
}

public sealed class RedundancyHint
{
    public RedundancyHint(RedundancyKind kind, string note)
    {
        Kind = kind;
        Note = note;
    }

    public RedundancyKind Kind { get; }

    /// <summary>Текст подсказки для оператора.</summary>
    public string Note { get; }
}

/// <summary>
/// База знаний о пакетах, которые на .NET Core / .NET 5+ либо являются пустыми фасадами,
/// либо давно входят в состав рантайма. Подсказки формулируются как гипотезы: убирать
/// такую ссылку можно только если её не тянет транзитивно чужой пакет.
/// </summary>
public static class FrameworkProvidedPackages
{
    /// <summary>
    /// Пакеты-контракты эпохи netstandard1.x: на .NET Core их содержимое — заглушка,
    /// реальные типы живут в рантайме. Появляются в графе только из очень старых зависимостей.
    /// </summary>
    private static readonly HashSet<string> LegacyContracts = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.NETCore.Platforms",
        "Microsoft.NETCore.Targets",
        "System.AppContext",
        "System.Collections",
        "System.Collections.Concurrent",
        "System.Collections.NonGeneric",
        "System.Collections.Specialized",
        "System.ComponentModel",
        "System.ComponentModel.Primitives",
        "System.ComponentModel.TypeConverter",
        "System.Console",
        "System.Diagnostics.Debug",
        "System.Diagnostics.Tools",
        "System.Diagnostics.Tracing",
        "System.Dynamic.Runtime",
        "System.Globalization",
        "System.Globalization.Calendars",
        "System.Globalization.Extensions",
        "System.IO",
        "System.IO.Compression",
        "System.IO.FileSystem",
        "System.IO.FileSystem.Primitives",
        "System.Linq",
        "System.Linq.Expressions",
        "System.Linq.Queryable",
        "System.Net.Http",
        "System.Net.NameResolution",
        "System.Net.Primitives",
        "System.Net.Requests",
        "System.Net.Sockets",
        "System.Net.WebHeaderCollection",
        "System.ObjectModel",
        "System.Reflection",
        "System.Reflection.Emit",
        "System.Reflection.Emit.ILGeneration",
        "System.Reflection.Emit.Lightweight",
        "System.Reflection.Extensions",
        "System.Reflection.Primitives",
        "System.Reflection.TypeExtensions",
        "System.Resources.ResourceManager",
        "System.Runtime",
        "System.Runtime.Extensions",
        "System.Runtime.Handles",
        "System.Runtime.InteropServices",
        "System.Runtime.InteropServices.RuntimeInformation",
        "System.Runtime.Numerics",
        "System.Runtime.Serialization.Primitives",
        "System.Security.Claims",
        "System.Security.Cryptography.Algorithms",
        "System.Security.Cryptography.Encoding",
        "System.Security.Cryptography.Primitives",
        "System.Security.Cryptography.X509Certificates",
        "System.Text.RegularExpressions",
        "System.Threading",
        "System.Threading.Tasks",
        "System.Threading.Tasks.Parallel",
        "System.Threading.Thread",
        "System.Threading.ThreadPool",
        "System.Threading.Timer",
        "System.Xml.ReaderWriter",
        "System.Xml.XDocument",
        "System.Xml.XmlDocument",
    };

    /// <summary>
    /// Пакеты, чьё содержимое вошло в состав рантайма начиная с указанной версии .NET.
    /// После этой версии ссылка на пакет обычно не нужна (или превращается в фасад).
    /// </summary>
    private static readonly Dictionary<string, Version> InBoxSince = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Microsoft.Bcl.AsyncInterfaces"] = new Version(5, 0),
        ["Microsoft.Bcl.HashCode"] = new Version(3, 0),
        ["System.Buffers"] = new Version(3, 0),
        ["System.Collections.Immutable"] = new Version(8, 0),
        ["System.ComponentModel.Annotations"] = new Version(5, 0),
        ["System.Diagnostics.DiagnosticSource"] = new Version(5, 0),
        ["System.Formats.Asn1"] = new Version(5, 0),
        ["System.Memory"] = new Version(3, 0),
        ["System.Numerics.Vectors"] = new Version(3, 0),
        ["System.Reflection.DispatchProxy"] = new Version(3, 0),
        ["System.Reflection.Metadata"] = new Version(8, 0),
        ["System.Runtime.CompilerServices.Unsafe"] = new Version(6, 0),
        ["System.Security.Cryptography.Cng"] = new Version(5, 0),
        ["System.Security.Cryptography.OpenSsl"] = new Version(5, 0),
        ["System.Security.Cryptography.Pkcs"] = new Version(7, 0),
        ["System.Security.Cryptography.Xml"] = new Version(8, 0),
        ["System.Security.Principal.Windows"] = new Version(5, 0),
        ["System.Text.Encodings.Web"] = new Version(3, 0),
        ["System.Text.Json"] = new Version(6, 0),
        ["System.Threading.Channels"] = new Version(3, 0),
        ["System.Threading.Tasks.Extensions"] = new Version(3, 0),
        ["System.ValueTuple"] = new Version(3, 0),
    };

    /// <summary>
    /// Пакеты, которые входят в shared framework ASP.NET Core: их прямые ссылки почти всегда лишние
    /// в веб-проектах (но нужны в библиотеках, которые собираются без FrameworkReference).
    /// </summary>
    private static readonly HashSet<string> AspNetCoreShared = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.AspNetCore.Http.Abstractions",
        "Microsoft.AspNetCore.Http.Features",
        "Microsoft.Extensions.ObjectPool",
        "System.IO.Pipelines",
    };

    public static RedundancyHint? TryGetHint(string packageId, Tfm targetTfm)
    {
        if (targetTfm.Family != TfmFamily.NetCoreApp)
            return null;

        if (LegacyContracts.Contains(packageId))
        {
            return new RedundancyHint(
                RedundancyKind.LegacyContract,
                $"Контрактный пакет эпохи .NET Standard 1.x. На {targetTfm.DisplayName} он не несёт кода — " +
                "типы берутся из рантайма. В графе оказался только потому, что его требует старая зависимость; " +
                "уходит сам, когда обновится виновник.");
        }

        if (InBoxSince.TryGetValue(packageId, out var since))
        {
            if (targetTfm.Version >= since)
            {
                var sinceName = since.Major >= 5 ? $".NET {since.Major}.{since.Minor}" : $".NET Core {since.Major}.{since.Minor}";
                return new RedundancyHint(
                    RedundancyKind.InBox,
                    $"Входит в состав рантайма начиная с {sinceName}. На {targetTfm.DisplayName} прямая ссылка, " +
                    "как правило, не нужна: если пакет виден только транзитивно — обновляйте виновника, " +
                    "если он прописан в csproj — попробуйте убрать ссылку.");
            }
        }

        if (AspNetCoreShared.Contains(packageId))
        {
            return new RedundancyHint(
                RedundancyKind.InBox,
                "Поставляется в составе shared framework Microsoft.AspNetCore.App. В веб-проекте прямая ссылка " +
                "обычно лишняя и только фиксирует старую версию.");
        }

        return null;
    }
}
