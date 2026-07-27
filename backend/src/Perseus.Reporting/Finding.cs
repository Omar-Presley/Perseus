namespace Perseus.Reporting;

public enum FindingStatus { Good, Warning, Bad, Info, Unknown }

public enum Severity { Info, Low, Medium, High, Critical }

/// <summary>
/// One audit result. Mirrors the finding shape from the PowerShell version
/// (Category/Name/Status/Severity/Detail/Recommendation/InternetExposed) so
/// the reporting and scoring logic ported over unchanged.
/// </summary>
public sealed class Finding
{
    public required string Category { get; init; }
    public required string Name { get; init; }
    public required FindingStatus Status { get; init; }
    public Severity Severity { get; init; } = Severity.Info;
    public string Detail { get; init; } = "";
    public string Recommendation { get; init; } = "N/A";
    public bool InternetExposed { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.Now;
}
