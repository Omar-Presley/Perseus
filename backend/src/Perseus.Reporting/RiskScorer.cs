namespace Perseus.Reporting;

/// <summary>
/// Direct port of Get-RiskScore/Get-RiskLevel from the PowerShell version.
/// Deductions are grouped per category before summing (capped at 40 points
/// per category) so a pile of unrelated low-severity findings in one bucket
/// can't outweigh a single Critical finding elsewhere. Internet-exposed
/// findings get a 1.25x weight.
/// </summary>
public sealed record CategoryRisk(string Category, int Deduction, int FindingCount, Severity WorstSeverity);

public static class RiskScorer
{
    private const int CategoryCap = 40;

    private static int SeverityWeight(Severity severity) => severity switch
    {
        Severity.Critical => 25,
        Severity.High => 15,
        Severity.Medium => 8,
        Severity.Low => 3,
        _ => 0
    };

    private static double FindingWeight(Finding f)
    {
        double weight = f.Status switch
        {
            FindingStatus.Bad => SeverityWeight(f.Severity),
            FindingStatus.Warning => Math.Ceiling(SeverityWeight(f.Severity) / 2.0),
            FindingStatus.Unknown => 2,
            _ => 0
        };

        return f.InternetExposed ? Math.Round(weight * 1.25) : weight;
    }

    public static int Score(IReadOnlyList<Finding> findings)
    {
        var totalDeduction = 0;

        foreach (var group in findings.GroupBy(f => f.Category))
        {
            double categoryDeduction = group.Sum(FindingWeight);
            categoryDeduction = Math.Min(categoryDeduction, CategoryCap);
            totalDeduction += (int)categoryDeduction;
        }

        return Math.Max(0, 100 - totalDeduction);
    }

    public static IReadOnlyList<CategoryRisk> CategoryBreakdown(IReadOnlyList<Finding> findings)
    {
        return findings
            .GroupBy(f => f.Category)
            .Select(group =>
            {
                var deduction = (int)Math.Min(group.Sum(FindingWeight), CategoryCap);
                var worst = group.Select(f => f.Severity).DefaultIfEmpty(Severity.Info).Max();
                return new CategoryRisk(group.Key, deduction, group.Count(), worst);
            })
            .OrderByDescending(c => c.Deduction)
            .ToList();
    }

    public static string Level(int score) => score switch
    {
        >= 85 => "LOW",
        >= 65 => "MEDIUM",
        >= 40 => "HIGH",
        _ => "CRITICAL"
    };
}
