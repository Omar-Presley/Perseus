using System.Text.Json;
using System.Text.Json.Serialization;

namespace Perseus.Reporting;

public static class JsonReportWriter
{
    public static string Write(FindingStore store, string reportDir)
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        var path = Path.Combine(reportDir, $"Perseus_AuditReport_{timestamp}.json");

        var score = RiskScorer.Score(store.All);
        var payload = new
        {
            Host = Environment.MachineName,
            Platform = PlatformHelper.Current.ToString(),
            Generated = DateTime.Now,
            Score = score,
            Level = RiskScorer.Level(score),
            Findings = store.All
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };

        File.WriteAllText(path, JsonSerializer.Serialize(payload, options));
        ConsoleUi.WriteStatus("OK", $"JSON report saved to: {path}", ConsoleColor.Green);
        return path;
    }
}
