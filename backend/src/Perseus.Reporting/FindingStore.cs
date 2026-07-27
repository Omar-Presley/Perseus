namespace Perseus.Reporting;

/// <summary>
/// Central findings collection. Equivalent of $Global:PerseusFindings plus
/// Add-Finding from the PowerShell version - every check provider (Windows/
/// macOS/Linux, in Perseus.Audit) writes into one shared instance of this
/// that's passed around explicitly rather than relying on global state,
/// since that's the idiomatic C# equivalent (no PowerShell-module-style
/// implicit scope sharing here - this class IS the shared state, passed by
/// reference).
/// </summary>
public sealed class FindingStore
{
    private readonly List<Finding> _findings = new();

    public IReadOnlyList<Finding> All => _findings;

    public void Add(Finding finding) => _findings.Add(finding);

    public void Add(string category, string name, FindingStatus status, string detail,
        string recommendation = "N/A", Severity severity = Severity.Info, bool internetExposed = false)
    {
        _findings.Add(new Finding
        {
            Category = category,
            Name = name,
            Status = status,
            Detail = detail,
            Recommendation = recommendation,
            Severity = severity,
            InternetExposed = internetExposed
        });
    }

    public void Clear() => _findings.Clear();

    public int CountByStatus(FindingStatus status) => _findings.Count(f => f.Status == status);
}
