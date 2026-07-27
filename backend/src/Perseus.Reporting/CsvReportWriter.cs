using System.Globalization;
using System.Text;

namespace Perseus.Reporting;

public static class CsvReportWriter
{
    public static string Write(FindingStore store, string reportDir)
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        var path = Path.Combine(reportDir, $"Perseus_AuditReport_{timestamp}.csv");

        var sb = new StringBuilder();
        sb.AppendLine("Category,Name,Status,Severity,InternetExposed,Detail,Recommendation,Timestamp");

        foreach (var f in store.All)
        {
            sb.AppendLine(string.Join(",",
                CsvField(f.Category),
                CsvField(f.Name),
                CsvField(f.Status.ToString()),
                CsvField(f.Severity.ToString()),
                CsvField(f.InternetExposed.ToString()),
                CsvField(f.Detail),
                CsvField(f.Recommendation),
                CsvField(f.Timestamp.ToString("O", CultureInfo.InvariantCulture))));
        }

        File.WriteAllText(path, sb.ToString());
        ConsoleUi.WriteStatus("OK", $"CSV report saved to: {path}", ConsoleColor.Green);
        return path;
    }

    private static string CsvField(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
        {
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
