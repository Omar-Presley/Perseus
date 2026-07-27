using System;
using System.Collections.ObjectModel;
using System.Linq;
using Perseus.Reporting;

namespace Perseus.ViewModels;

public partial class MainViewModel
{
    private DateTime? _lastScanAt;

    public ObservableCollection<CategoryRisk> CategoryBreakdown { get; } = new();

    public ObservableCollection<Finding> TopFindings { get; } = new();

    public ObservableCollection<SoftwareItem> SoftwareInventory { get; } = new();

    private int _cveFindingCount;

    public int CveFindingCount
    {
        get => _cveFindingCount;
        set => SetProperty(ref _cveFindingCount, value);
    }

    public DateTime? LastScanAt
    {
        get => _lastScanAt;
        set => SetProperty(ref _lastScanAt, value);
    }

    private void InitializeDashboardState()
    {
        // Nothing to wire beyond the collections above; populated once a scan runs.
    }

    private void UpdateDashboardSummary(System.Collections.Generic.IReadOnlyList<Finding> findings)
    {
        CategoryBreakdown.Clear();
        foreach (var category in RiskScorer.CategoryBreakdown(findings))
        {
            CategoryBreakdown.Add(category);
        }

        TopFindings.Clear();
        foreach (var finding in findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Timestamp).Take(8))
        {
            TopFindings.Add(finding);
        }

        CveFindingCount = findings.Count(f => f.Category == "CVE");
    }

    private void RefreshSoftwareInventory()
    {
        SoftwareInventory.Clear();
        foreach (var item in _lastSoftware)
        {
            SoftwareInventory.Add(item);
        }
    }
}
