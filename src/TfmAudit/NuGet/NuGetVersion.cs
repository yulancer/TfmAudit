using System.Globalization;

namespace TfmAudit.NuGet;

/// <summary>
/// Минимальная реализация семантики версий NuGet: 4 числовых компонента, pre-release-метка,
/// build-метаданные. Достаточно для сортировки и сравнения версий из фида.
/// </summary>
public sealed class NuGetVersion : IComparable<NuGetVersion>, IEquatable<NuGetVersion>
{
    private NuGetVersion(string original, int[] parts, string[] preRelease)
    {
        Original = original;
        _parts = parts;
        _preRelease = preRelease;
    }

    private readonly int[] _parts;
    private readonly string[] _preRelease;

    public string Original { get; }

    public int Major => _parts.Length > 0 ? _parts[0] : 0;

    public int Minor => _parts.Length > 1 ? _parts[1] : 0;

    public int Patch => _parts.Length > 2 ? _parts[2] : 0;

    public bool IsPreRelease => _preRelease.Length > 0;

    public static bool TryParse(string? text, out NuGetVersion version)
    {
        version = null!;
        if (string.IsNullOrWhiteSpace(text)) return false;

        var s = text!.Trim();

        var plus = s.IndexOf('+');
        if (plus >= 0) s = s.Substring(0, plus);

        var dash = s.IndexOf('-');
        var numeric = dash >= 0 ? s.Substring(0, dash) : s;
        var pre = dash >= 0 ? s.Substring(dash + 1) : string.Empty;

        var chunks = numeric.Split('.');
        if (chunks.Length == 0 || chunks.Length > 4) return false;

        var parts = new int[chunks.Length];
        for (var i = 0; i < chunks.Length; i++)
        {
            if (!int.TryParse(chunks[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out parts[i]) || parts[i] < 0)
                return false;
        }

        var preParts = pre.Length == 0
            ? Array.Empty<string>()
            : pre.Split('.', StringSplitOptions.RemoveEmptyEntries);

        version = new NuGetVersion(text!.Trim(), parts, preParts);
        return true;
    }

    public int CompareTo(NuGetVersion? other)
    {
        if (other is null) return 1;

        var len = Math.Max(_parts.Length, other._parts.Length);
        for (var i = 0; i < len; i++)
        {
            var a = i < _parts.Length ? _parts[i] : 0;
            var b = i < other._parts.Length ? other._parts[i] : 0;
            if (a != b) return a.CompareTo(b);
        }

        if (_preRelease.Length == 0 && other._preRelease.Length == 0) return 0;
        if (_preRelease.Length == 0) return 1;   // релиз старше pre-release
        if (other._preRelease.Length == 0) return -1;

        var pl = Math.Max(_preRelease.Length, other._preRelease.Length);
        for (var i = 0; i < pl; i++)
        {
            if (i >= _preRelease.Length) return -1;
            if (i >= other._preRelease.Length) return 1;

            var x = _preRelease[i];
            var y = other._preRelease[i];
            var xNum = int.TryParse(x, NumberStyles.Integer, CultureInfo.InvariantCulture, out var xi);
            var yNum = int.TryParse(y, NumberStyles.Integer, CultureInfo.InvariantCulture, out var yi);

            if (xNum && yNum)
            {
                if (xi != yi) return xi.CompareTo(yi);
            }
            else if (xNum)
            {
                return -1;
            }
            else if (yNum)
            {
                return 1;
            }
            else
            {
                var c = string.Compare(x, y, StringComparison.OrdinalIgnoreCase);
                if (c != 0) return c;
            }
        }

        return 0;
    }

    public bool Equals(NuGetVersion? other) => CompareTo(other) == 0;

    public override bool Equals(object? obj) => Equals(obj as NuGetVersion);

    public override int GetHashCode() => (Major, Minor, Patch, IsPreRelease).GetHashCode();

    public override string ToString() => Original;
}
