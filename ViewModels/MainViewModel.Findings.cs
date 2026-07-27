using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Perseus.Reporting;

namespace Perseus.ViewModels;

public enum FindingsSortMode
{
    Severity,
    Category,
    Name,
    Timestamp
}

public sealed class FindingRowViewModel
{
    public FindingRowViewModel(Finding finding)
    {
        Finding = finding;
    }

    public Finding Finding { get; }

    public string Category => Finding.Category;
    public string Name => Finding.Name;
    public FindingStatus Status => Finding.Status;
    public Severity Severity => Finding.Severity;
    public string Detail => Finding.Detail;
    public string Recommendation => Finding.Recommendation;
    public bool InternetExposed => Finding.InternetExposed;
    public DateTime Timestamp => Finding.Timestamp;
    public bool IsCveRelated => Finding.Category == "CVE";
}

public sealed class FindingCategoryGroup
{
    public FindingCategoryGroup(string category, ObservableCollection<Finding> items)
    {
        Category = category;
        Items = items;
    }

    public string Category { get; }
    public int Count => Items.Count;
    public ObservableCollection<Finding> Items { get; }
}

public partial class MainViewModel
{
    private const string AllFilterOption = "All";

    private string _selectedCategoryFilter = AllFilterOption;
    private string _selectedSeverityFilter = AllFilterOption;
    private string _selectedStatusFilter = AllFilterOption;
    private string _findingsSearchText = string.Empty;
    private FindingsSortMode _findingsSortMode = FindingsSortMode.Severity;

    public ObservableCollection<string> AvailableCategories { get; } = new() { AllFilterOption };
    public ObservableCollection<string> AvailableSeverities { get; } = new(new[] { AllFilterOption }.Concat(Enum.GetNames(typeof(Severity))));
    public ObservableCollection<string> AvailableStatuses { get; } = new(new[] { AllFilterOption }.Concat(Enum.GetNames(typeof(FindingStatus))));
    public ObservableCollection<FindingsSortMode> SortModes { get; } = new(Enum.GetValues<FindingsSortMode>());

    public ObservableCollection<FindingRowViewModel> FilteredFindings { get; } = new();
    public ObservableCollection<FindingCategoryGroup> FindingGroups { get; } = new();

    public string SelectedCategoryFilter
    {
        get => _selectedCategoryFilter;
        set { SetProperty(ref _selectedCategoryFilter, value); ApplyFindingsFilter(); }
    }

    public string SelectedSeverityFilter
    {
        get => _selectedSeverityFilter;
        set { SetProperty(ref _selectedSeverityFilter, value); ApplyFindingsFilter(); }
    }

    public string SelectedStatusFilter
    {
        get => _selectedStatusFilter;
        set { SetProperty(ref _selectedStatusFilter, value); ApplyFindingsFilter(); }
    }

    public string FindingsSearchText
    {
        get => _findingsSearchText;
        set { SetProperty(ref _findingsSearchText, value); ApplyFindingsFilter(); }
    }

    public FindingsSortMode FindingsSortMode
    {
        get => _findingsSortMode;
        set { SetProperty(ref _findingsSortMode, value); ApplyFindingsFilter(); }
    }

    private void InitializeFindingsState()
    {
        // Filter/sort defaults are set via field initializers above.
    }

    private void RebuildFindingGroups()
    {
        var categories = Findings.Select(f => f.Category).Distinct().OrderBy(c => c).ToList();

        AvailableCategories.Clear();
        AvailableCategories.Add(AllFilterOption);
        foreach (var category in categories) AvailableCategories.Add(category);

        FindingGroups.Clear();
        foreach (var category in categories)
        {
            var items = new ObservableCollection<Finding>(Findings.Where(f => f.Category == category));
            FindingGroups.Add(new FindingCategoryGroup(category, items));
        }
    }

    private void ApplyFindingsFilter()
    {
        IEnumerable<Finding> query = Findings;

        if (SelectedCategoryFilter != AllFilterOption)
        {
            query = query.Where(f => f.Category == SelectedCategoryFilter);
        }

        if (SelectedSeverityFilter != AllFilterOption && Enum.TryParse<Severity>(SelectedSeverityFilter, out var severity))
        {
            query = query.Where(f => f.Severity == severity);
        }

        if (SelectedStatusFilter != AllFilterOption && Enum.TryParse<FindingStatus>(SelectedStatusFilter, out var status))
        {
            query = query.Where(f => f.Status == status);
        }

        if (!string.IsNullOrWhiteSpace(FindingsSearchText))
        {
            var text = FindingsSearchText.Trim();
            query = query.Where(f =>
                f.Name.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                f.Detail.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                f.Category.Contains(text, StringComparison.OrdinalIgnoreCase));
        }

        query = FindingsSortMode switch
        {
            FindingsSortMode.Severity => query.OrderByDescending(f => f.Severity).ThenBy(f => f.Category),
            FindingsSortMode.Category => query.OrderBy(f => f.Category).ThenByDescending(f => f.Severity),
            FindingsSortMode.Name => query.OrderBy(f => f.Name),
            FindingsSortMode.Timestamp => query.OrderByDescending(f => f.Timestamp),
            _ => query
        };

        FilteredFindings.Clear();
        foreach (var finding in query)
        {
            FilteredFindings.Add(new FindingRowViewModel(finding));
        }
    }
}
