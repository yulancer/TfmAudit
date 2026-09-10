namespace TfmAudit.Reporting;

/// <summary>Русские числительные — чтобы в отчётах не было «64 находок» вместо «64 находки».</summary>
public static class Ru
{
    /// <summary>Выбирает форму слова по числу: 1 находка, 2 находки, 5 находок.</summary>
    public static string Plural(int n, string one, string few, string many)
    {
        var mod10 = Math.Abs(n) % 10;
        var mod100 = Math.Abs(n) % 100;

        if (mod10 == 1 && mod100 != 11) return one;
        if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
        return many;
    }

    public static string Count(int n, string one, string few, string many) => $"{n} {Plural(n, one, few, many)}";

    /// <summary>Именительный падеж: «1 находка», «2 находки», «5 находок».</summary>
    public static string Findings(int n) => Count(n, "находка", "находки", "находок");

    /// <summary>Винительный падеж: «затрагивает 1 находку», «2 находки», «5 находок».</summary>
    public static string FindingsAccusative(int n) => Count(n, "находку", "находки", "находок");

    public static string Packages(int n) => Count(n, "пакет", "пакета", "пакетов");

    public static string Generations(int n) => Count(n, "поколение", "поколения", "поколений");

    public static string Dependencies(int n) => Count(n, "зависимость", "зависимости", "зависимостей");
}
