using System.Net;
using System.Text;

namespace Perseus.Reporting;

public sealed record SoftwareItem(string Name, string Version, string? Publisher, string Source);

public static class HtmlReportWriter
{
    public static string Write(FindingStore store, IReadOnlyList<SoftwareItem> software, string reportDir)
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        var path = Path.Combine(reportDir, $"Perseus_AuditReport_{timestamp}.html");

        var score = RiskScorer.Score(store.All);
        var level = RiskScorer.Level(score);
        var levelColor = level switch
        {
            "LOW" => "#2ecc71",
            "MEDIUM" => "#f39c12",
            "HIGH" => "#e67e22",
            _ => "#e74c3c"
        };

        var rows = new StringBuilder();
        foreach (var f in store.All.OrderByDescending(SeverityRank))
        {
            var color = f.Status switch
            {
                FindingStatus.Bad => "#e74c3c",
                FindingStatus.Warning => "#f39c12",
                FindingStatus.Good => "#2ecc71",
                _ => "#7f8c8d"
            };
            rows.Append($"<tr><td>{Enc(f.Category)}</td><td>{Enc(f.Name)}</td>" +
                        $"<td style='color:{color};font-weight:bold'>{Enc(f.Status.ToString())}</td>" +
                        $"<td>{Enc(f.Severity.ToString())}</td><td>{Enc(f.Detail)}</td>" +
                        $"<td>{Enc(f.Recommendation)}</td></tr>\n");
        }

        var softwareRows = new StringBuilder();
        foreach (var s in software)
        {
            softwareRows.Append($"<tr><td>{Enc(s.Name)}</td><td>{Enc(s.Version)}</td>" +
                                 $"<td>{Enc(s.Publisher ?? "")}</td><td>{Enc(s.Source)}</td></tr>\n");
        }

        var bad = store.CountByStatus(FindingStatus.Bad);
        var warn = store.CountByStatus(FindingStatus.Warning);

        var html = $$"""
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>Project Perseus - Security Audit Report - {{Enc(Environment.MachineName)}}</title>
        <style>
          body { font-family: 'Segoe UI', Arial, sans-serif; background:#1e1e2f; color:#e0e0e0; margin:0; padding:2rem; }
          h1 { color:#00d4ff; margin-bottom:0.2rem; }
          .subtitle { color:#00d4ff; font-size:0.95rem; margin-bottom:1rem; }
          .summary { display:flex; gap:2rem; margin-bottom:2rem; }
          .card { background:#2a2a3d; padding:1.5rem; border-radius:10px; flex:1; text-align:center; }
          .score { font-size:3rem; font-weight:bold; color:{{levelColor}}; }
          table { width:100%; border-collapse:collapse; margin-bottom:2rem; }
          th, td { padding:8px 12px; border-bottom:1px solid #3a3a4d; text-align:left; font-size:0.9rem; }
          th { background:#2a2a3d; color:#00d4ff; }
          tr:hover { background:#2f2f45; }
          .meta { color:#999; font-size:0.85rem; margin-bottom:1.5rem; }
        </style>
        </head>
        <body>
          <h1>Project Perseus</h1>
          <div class="subtitle">PowerShell Endpoint Review and Security Evaluation Utility Suite - C#/.NET core</div>
          <div class="meta">Host: {{Enc(Environment.MachineName)}} &nbsp;|&nbsp; Platform: {{PlatformHelper.Current}} &nbsp;|&nbsp; Generated: {{DateTime.Now}}</div>

          <div class="summary">
            <div class="card"><div class="score">{{score}}</div>Risk Score / 100</div>
            <div class="card"><div class="score" style="color:{{levelColor}}">{{level}}</div>Risk Level</div>
            <div class="card"><div class="score" style="color:#e74c3c">{{bad}}</div>Bad Findings</div>
            <div class="card"><div class="score" style="color:#f39c12">{{warn}}</div>Warnings</div>
          </div>

          <h2>Findings</h2>
          <table>
            <tr><th>Category</th><th>Name</th><th>Status</th><th>Severity</th><th>Detail</th><th>Recommendation</th></tr>
            {{rows}}
          </table>

          <h2>Installed Software ({{software.Count}})</h2>
          <table>
            <tr><th>Name</th><th>Version</th><th>Publisher</th><th>Source</th></tr>
            {{softwareRows}}
          </table>
        </body>
        </html>
        """;

        File.WriteAllText(path, html);
        ConsoleUi.WriteStatus("OK", $"HTML report saved to: {path}", ConsoleColor.Green);
        return path;
    }

    private static int SeverityRank(Finding f) => f.Severity switch
    {
        Severity.Critical => 4,
        Severity.High => 3,
        Severity.Medium => 2,
        Severity.Low => 1,
        _ => 0
    };

    private static string Enc(string s) => WebUtility.HtmlEncode(s);
}
