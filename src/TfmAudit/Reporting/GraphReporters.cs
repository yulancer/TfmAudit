using System.Text;
using TfmAudit.Analysis;

namespace TfmAudit.Reporting;

/// <summary>Graphviz DOT: по одному подграфу на таргет.</summary>
public static class DotReporter
{
    public static string Render(AuditReport report, bool problemPathsOnly = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("// tfm-audit — граф зависимостей");
        sb.AppendLine("// Рендер: dot -Tsvg tfm-audit.dot -o tfm-audit.svg");
        sb.AppendLine("digraph dependencies {");
        sb.AppendLine("  rankdir=LR;");
        sb.AppendLine("  graph [fontname=\"Segoe UI,Helvetica,sans-serif\", fontsize=10, splines=true, nodesep=0.25, ranksep=0.9];");
        sb.AppendLine("  node  [fontname=\"Segoe UI,Helvetica,sans-serif\", fontsize=9, shape=box, style=\"rounded,filled\", color=\"#c8ccd4\", fillcolor=\"#ffffff\"];");
        sb.AppendLine("  edge  [fontname=\"Segoe UI,Helvetica,sans-serif\", fontsize=7, color=\"#b6bcc8\", arrowsize=0.6];");

        var cluster = 0;
        foreach (var project in report.Projects)
        {
            foreach (var fw in project.Frameworks)
            {
                var prefix = $"c{cluster}";
                sb.AppendLine();
                sb.AppendLine($"  subgraph cluster_{cluster} {{");
                sb.AppendLine($"    label=\"{Escape(project.Name)} · {Escape(fw.Alias)} ({Escape(fw.Tfm.DisplayName)})\";");
                sb.AppendLine("    labeljust=l; fontsize=12; style=\"rounded\"; color=\"#9aa2b1\";");

                var keep = SelectNodes(fw, problemPathsOnly);

                foreach (var node in fw.Graph.Nodes)
                {
                    if (!keep.Contains(node.Id)) continue;

                    var (fill, border, penwidth) = node.Severity switch
                    {
                        "error" => ("#fde8e8", "#c0392b", "1.6"),
                        "warning" => ("#fdf3e2", "#b8791b", "1.3"),
                        "info" => ("#eef2fb", "#5b6b95", "1.0"),
                        _ => (node.IsDirect ? "#eaf6ee" : "#ffffff", node.IsDirect ? "#3f8f5b" : "#c8ccd4", node.IsDirect ? "1.4" : "1.0"),
                    };

                    var shape = node.IsProject ? "folder" : node.IsDirect ? "box" : "box";
                    var label = $"{Escape(node.Id)}\\n{Escape(node.Version)}  ·  {Escape(node.AssetTfm)}";

                    sb.AppendLine($"    \"{prefix}_{Escape(node.Id)}\" [label=\"{label}\", fillcolor=\"{fill}\", color=\"{border}\", penwidth={penwidth}, shape={shape}];");
                }

                foreach (var edge in fw.Graph.Edges)
                {
                    if (!keep.Contains(edge.From) || !keep.Contains(edge.To)) continue;
                    if (problemPathsOnly && !edge.OnProblemPath) continue;

                    var attrs = new List<string>();
                    if (edge.OnProblemPath)
                    {
                        attrs.Add("color=\"#c0392b\"");
                        attrs.Add("penwidth=1.4");
                    }

                    if (edge.Range is not null) attrs.Add($"label=\"{Escape(Compact(edge.Range))}\"");

                    var attrText = attrs.Count > 0 ? " [" + string.Join(", ", attrs) + "]" : string.Empty;
                    sb.AppendLine($"    \"{prefix}_{Escape(edge.From)}\" -> \"{prefix}_{Escape(edge.To)}\"{attrText};");
                }

                sb.AppendLine("  }");
                cluster++;
            }
        }

        sb.AppendLine("}");
        return sb.ToString();
    }

    /// <summary>Оставляем находки, корни и всё, что лежит на путях между ними.</summary>
    internal static HashSet<string> SelectNodes(FrameworkAnalysis fw, bool problemPathsOnly)
    {
        if (!problemPathsOnly)
            return new HashSet<string>(fw.Graph.Nodes.Select(n => n.Id), StringComparer.OrdinalIgnoreCase);

        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in fw.Findings)
        {
            keep.Add(f.PackageId);
            foreach (var chain in f.Chains)
                foreach (var step in chain.Steps)
                    keep.Add(step.Id);
        }

        return keep;
    }

    private static string Compact(string range) => range.Replace(", )", ",)").Replace(" ", string.Empty);

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}

/// <summary>DGML — формат графов Visual Studio (Architecture → Directed Graph Document).</summary>
public static class DgmlReporter
{
    public static string Render(AuditReport report, bool problemPathsOnly = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        sb.AppendLine("<DirectedGraph xmlns=\"http://schemas.microsoft.com/vs/2009/dgml\" GraphDirection=\"LeftToRight\" Layout=\"Sugiyama\">");

        var nodes = new StringBuilder();
        var links = new StringBuilder();
        var groups = new HashSet<string>(StringComparer.Ordinal);

        nodes.AppendLine("  <Nodes>");
        links.AppendLine("  <Links>");

        foreach (var project in report.Projects)
        {
            foreach (var fw in project.Frameworks)
            {
                var groupId = $"{project.Name}|{fw.Alias}";
                if (groups.Add(groupId))
                {
                    nodes.AppendLine($"    <Node Id=\"{X(groupId)}\" Label=\"{X(project.Name)} · {X(fw.Alias)}\" Group=\"Expanded\" Category=\"Target\" />");
                }

                var keep = DotReporter.SelectNodes(fw, problemPathsOnly);

                foreach (var node in fw.Graph.Nodes)
                {
                    if (!keep.Contains(node.Id)) continue;
                    var id = $"{groupId}/{node.Id}";
                    var category = node.Severity switch
                    {
                        "error" => "Error",
                        "warning" => "Warning",
                        "info" => "Info",
                        _ => node.IsDirect ? "DirectOk" : "Ok",
                    };

                    nodes.AppendLine(
                        $"    <Node Id=\"{X(id)}\" Label=\"{X(node.Id)} {X(node.Version)}\" Category=\"{category}\" " +
                        $"AssetTfm=\"{X(node.AssetTfm)}\" Depth=\"{node.Depth}\" Direct=\"{(node.IsDirect ? "да" : "нет")}\" />");

                    links.AppendLine($"    <Link Source=\"{X(groupId)}\" Target=\"{X(id)}\" Category=\"Contains\" />");
                }

                foreach (var edge in fw.Graph.Edges)
                {
                    if (!keep.Contains(edge.From) || !keep.Contains(edge.To)) continue;
                    if (problemPathsOnly && !edge.OnProblemPath) continue;

                    links.AppendLine(
                        $"    <Link Source=\"{X($"{groupId}/{edge.From}")}\" Target=\"{X($"{groupId}/{edge.To}")}\" " +
                        $"Label=\"{X(edge.Range ?? string.Empty)}\" Category=\"{(edge.OnProblemPath ? "ProblemPath" : "Dependency")}\" />");
                }
            }
        }

        nodes.AppendLine("  </Nodes>");
        links.AppendLine("  </Links>");

        sb.Append(nodes);
        sb.Append(links);

        sb.AppendLine("  <Categories>");
        sb.AppendLine("    <Category Id=\"Target\" Label=\"Таргет\" Background=\"#EEF1F6\" />");
        sb.AppendLine("    <Category Id=\"Error\" Label=\"Ассет отстаёт на 2+ поколения\" Background=\"#F8D7DA\" Stroke=\"#C0392B\" />");
        sb.AppendLine("    <Category Id=\"Warning\" Label=\"Ассет отстаёт на 1 поколение\" Background=\"#FCEFD6\" Stroke=\"#B8791B\" />");
        sb.AppendLine("    <Category Id=\"Info\" Label=\"netstandard / только MSBuild-ассеты\" Background=\"#E7EDF9\" Stroke=\"#5B6B95\" />");
        sb.AppendLine("    <Category Id=\"DirectOk\" Label=\"Прямая зависимость, ассет актуален\" Background=\"#E4F5E9\" Stroke=\"#3F8F5B\" />");
        sb.AppendLine("    <Category Id=\"Ok\" Label=\"Ассет актуален\" Background=\"#FFFFFF\" />");
        sb.AppendLine("    <Category Id=\"ProblemPath\" Label=\"Путь до находки\" Stroke=\"#C0392B\" StrokeThickness=\"2\" />");
        sb.AppendLine("    <Category Id=\"Dependency\" Label=\"Зависимость\" />");
        sb.AppendLine("  </Categories>");

        sb.AppendLine("  <Properties>");
        sb.AppendLine("    <Property Id=\"AssetTfm\" Label=\"TFM ассета\" DataType=\"System.String\" />");
        sb.AppendLine("    <Property Id=\"Depth\" Label=\"Глубина\" DataType=\"System.Int32\" />");
        sb.AppendLine("    <Property Id=\"Direct\" Label=\"Прямая\" DataType=\"System.String\" />");
        sb.AppendLine("  </Properties>");

        sb.AppendLine("</DirectedGraph>");
        return sb.ToString();
    }

    private static string X(string s) => s
        .Replace("&", "&amp;")
        .Replace("<", "&lt;")
        .Replace(">", "&gt;")
        .Replace("\"", "&quot;")
        .Replace("'", "&apos;");
}
