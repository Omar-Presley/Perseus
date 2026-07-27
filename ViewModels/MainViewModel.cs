using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Platform.Storage;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Perseus.Audit;
using Perseus.Cve;
using Perseus.Models;
using Perseus.Network;
using Perseus.Reporting;

namespace Perseus.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    // Tab order: Dashboard, Findings, Network, Remediation, AI Assistant, Reports, Settings, About.
    public const int RemediationTabIndex = 3;
    public const int AssistantTabIndex = 4;

    private readonly FindingStore _store = new();
    private readonly List<SoftwareItem> _lastSoftware = new();
    private AuditSettings _settings;
    private readonly AuditSignatures _signatures;
    private readonly ICheckProvider _provider;
    private readonly string _configDir;
    private readonly string _reportDir;
    private readonly UiSettings _uiSettings;

    private int _selectedTabIndex;
    private string _statusMessage = "Ready to inspect the endpoint.";
    private int _overallScore = 100;
    private string _riskLevel = "LOW";
    private int _criticalCount;
    private int _highCount;
    private int _mediumCount;
    private int _lowCount;
    private int _warningCount;
    private int _infoCount;
    private int _goodCount;
    private bool _isBusy;
    private bool _enableCveLookup = true;
    private bool _generateHtml = true;
    private bool _generateJson = true;
    private bool _enableParallelAudit;
    private string _reportFolder = string.Empty;

    public string PlatformLabel { get; } = PlatformHelper.Current.ToString().ToUpperInvariant();

    public ObservableCollection<Finding> Findings { get; } = new();

    public ObservableCollection<string> AuditModules { get; } = new();

    public ObservableCollection<string> Logs { get; } = new();

    private void AddLog(string message)
    {
        try
        {
            var entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            Logs.Insert(0, entry);
            if (Logs.Count > 500) Logs.RemoveAt(Logs.Count - 1);
        }
        catch { /* best-effort logging */ }
    }

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set => SetProperty(ref _selectedTabIndex, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public int OverallScore
    {
        get => _overallScore;
        set => SetProperty(ref _overallScore, value);
    }

    public string RiskLevel
    {
        get => _riskLevel;
        set => SetProperty(ref _riskLevel, value);
    }

    public int CriticalCount
    {
        get => _criticalCount;
        set => SetProperty(ref _criticalCount, value);
    }

    public int HighCount
    {
        get => _highCount;
        set => SetProperty(ref _highCount, value);
    }

    public int MediumCount
    {
        get => _mediumCount;
        set => SetProperty(ref _mediumCount, value);
    }

    public int LowCount
    {
        get => _lowCount;
        set => SetProperty(ref _lowCount, value);
    }

    public int WarningCount
    {
        get => _warningCount;
        set => SetProperty(ref _warningCount, value);
    }

    public int InfoCount
    {
        get => _infoCount;
        set => SetProperty(ref _infoCount, value);
    }

    public int GoodCount
    {
        get => _goodCount;
        set => SetProperty(ref _goodCount, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    public bool EnableCveLookup
    {
        get => _enableCveLookup;
        set => SetProperty(ref _enableCveLookup, value);
    }

    public bool GenerateHtml
    {
        get => _generateHtml;
        set => SetProperty(ref _generateHtml, value);
    }

    public bool GenerateJson
    {
        get => _generateJson;
        set => SetProperty(ref _generateJson, value);
    }

    public bool EnableParallelAudit
    {
        get => _enableParallelAudit;
        set => SetProperty(ref _enableParallelAudit, value);
    }

    public string ReportFolder
    {
        get => _reportFolder;
        set => SetProperty(ref _reportFolder, value);
    }

    public AsyncRelayCommand RunFullAuditCommand { get; }
    public AsyncRelayCommand RefreshNetworkCommand { get; }
    public AsyncRelayCommand GenerateHtmlReportCommand { get; }
    public AsyncRelayCommand GenerateJsonReportCommand { get; }
    public AsyncRelayCommand GenerateCsvReportCommand { get; }
    public RelayCommand SaveSettingsCommand { get; }
    public AsyncRelayCommand BrowseReportsFolderCommand { get; }
    public RelayCommand OpenReportsFolderCommand { get; }
    public RelayCommand ClearLogsCommand { get; }
    public AsyncRelayCommand ExportLogsCommand { get; }
    public RelayCommand GoToRemediationCommand { get; }

    private string _activeCheck = string.Empty;
    private double _progress;

    public string ActiveCheck
    {
        get => _activeCheck;
        set => SetProperty(ref _activeCheck, value);
    }

    public double Progress
    {
        get => _progress;
        set => SetProperty(ref _progress, value);
    }

    public MainViewModel()
    {
        _configDir = Path.Combine(AppContext.BaseDirectory, "config");
        _reportDir = Path.Combine(AppContext.BaseDirectory, "reports");
        Directory.CreateDirectory(_configDir);
        Directory.CreateDirectory(_reportDir);

        _settings = ConfigLoader.LoadSettings(_configDir);
        _signatures = ConfigLoader.LoadSignatures(_configDir);
        _provider = PlatformHelper.Current switch
        {
            Platform.Windows => new WindowsCheckProvider(_settings, _signatures),
            Platform.Linux => new LinuxCheckProvider(_settings, _signatures),
            Platform.MacOs => new MacCheckProvider(_settings, _signatures),
            _ => throw new PlatformNotSupportedException($"Unsupported platform: {PlatformHelper.Current}")
        };

        _uiSettings = UiSettings.Load(Path.Combine(_configDir, "ui-settings.json"));
        EnableCveLookup = _uiSettings.EnableCveLookup;
        GenerateHtml = _uiSettings.GenerateHtml;
        GenerateJson = _uiSettings.GenerateJson;
        EnableParallelAudit = _uiSettings.EnableParallelAudit;
        ReportFolder = string.IsNullOrWhiteSpace(_uiSettings.ReportFolder) ? _reportDir : _uiSettings.ReportFolder;

        foreach (var check in _provider.Checks)
        {
            AuditModules.Add(check.Label);
        }

        RunFullAuditCommand = new AsyncRelayCommand(async _ => await RunFullAuditAsync());
        RefreshNetworkCommand = new AsyncRelayCommand(async _ => await RefreshNetworkAsync());
        GenerateHtmlReportCommand = new AsyncRelayCommand(async _ => await GenerateHtmlReportAsync());
        GenerateJsonReportCommand = new AsyncRelayCommand(async _ => await GenerateJsonReportAsync());
        GenerateCsvReportCommand = new AsyncRelayCommand(async _ => await GenerateCsvReportAsync());
        SaveSettingsCommand = new RelayCommand(_ => SaveSettings());
        BrowseReportsFolderCommand = new AsyncRelayCommand(async _ => await BrowseReportsFolderAsync());
        OpenReportsFolderCommand = new RelayCommand(_ => OpenReportsFolder());

        ClearLogsCommand = new RelayCommand(_ => { Logs.Clear(); StatusMessage = "Logs cleared."; });
        ExportLogsCommand = new AsyncRelayCommand(async _ => await ExportLogsAsync());
        GoToRemediationCommand = new RelayCommand(_ => { SelectedTabIndex = RemediationTabIndex; });

        InitializeDashboardState();
        InitializeFindingsState();
        InitializeNetworkState();
        InitializeReportsState();
        InitializeSettingsState();
        InitializeRemediationState();
        InitializeAssistantState();

        StatusMessage = "Ready to run a full audit or inspect the current network view.";
    }

    private async Task RunFullAuditAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        StatusMessage = "Running the audit checks...";
        AddLog("Starting full audit");
        ActiveCheck = string.Empty;
        Progress = 0.0;
        Findings.Clear();
        _store.Clear();

        var checks = _provider.Checks.ToList();
        var totalSteps = checks.Count + 1; // include port scan
        var completed = 0;

        try
        {
            foreach (var check in checks)
            {
                ActiveCheck = check.Label;
                try
                {
                    AddLog($"Running check: {check.Label}");
                    await check.Run(_store);
                    AddLog($"Completed check: {check.Label}");
                }
                catch (Exception ex)
                {
                    // don't crash entire audit - record a warning and continue
                    _store.Add("Audit", check.Label, FindingStatus.Warning, $"Check failed: {ex.Message}");
                    StatusMessage = $"Check {check.Label} failed: {ex.Message}";
                    AddLog($"Check failed: {check.Label} - {ex.Message}");
                }

                completed++;
                Progress = (completed / (double)totalSteps) * 100.0;
            }

            // Port scan (platform independent) - one scan feeds both the findings
            // store and the Network tab's live port list.
            ActiveCheck = "Network port scan";
            try
            {
                AddLog("Running network port scan");
                var ports = await PortScanner.GetListeningPortsAsync();
                ApplyPortScanResults(ports);
                await PortScanner.RunCheckAsync(_store, _settings.RiskyPorts, ports);
                AddLog("Port scan completed");
            }
            catch (Exception ex)
            {
                _store.Add("Network", "Port scan failed", FindingStatus.Warning, ex.Message);
                StatusMessage = $"Port scanner failed: {ex.Message}";
                AddLog($"Port scan failed: {ex.Message}");
            }
            completed++;
            Progress = (completed / (double)totalSteps) * 100.0;

            // Software inventory and CVE lookup (best-effort)
            _lastSoftware.Clear();
            try
            {
                AddLog("Collecting software inventory");
                var inventory = await _provider.GetSoftwareInventoryAsync(_store);
                if (inventory is not null) _lastSoftware.AddRange(inventory);
                AddLog($"Inventory items: {_lastSoftware.Count}");
            }
            catch (Exception ex)
            {
                _store.Add("Inventory", "Software inventory failed", FindingStatus.Warning, ex.Message);
                AddLog($"Inventory failed: {ex.Message}");
            }

            if (EnableCveLookup && _lastSoftware.Count > 0)
            {
                ActiveCheck = "CVE lookup";
                try
                {
                    AddLog("Starting CVE lookup");
                    await CveLookup.RunAsync(_store, _lastSoftware, _settings, _signatures);
                    AddLog("CVE lookup completed");
                }
                catch (Exception ex)
                {
                    _store.Add("CVE", "Lookup failed", FindingStatus.Warning, ex.Message);
                    StatusMessage = $"CVE lookup failed: {ex.Message}";
                    AddLog($"CVE lookup failed: {ex.Message}");
                }
            }

            RefreshFindings();
            UpdateSummary();
            RefreshSoftwareInventory();
            LastScanAt = DateTime.Now;
            StatusMessage = "Audit complete. Review the findings or export a report.";
            ActiveCheck = string.Empty;
            Progress = 100.0;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Audit failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshNetworkAsync()
    {
        try
        {
            var ports = await PortScanner.GetListeningPortsAsync();
            ApplyPortScanResults(ports);

            StatusMessage = ports.Count > 0
                ? $"Discovered {ports.Count} listening ports."
                : "No listening ports were detected.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Unable to refresh network data: {ex.Message}";
        }
    }

    private async Task GenerateHtmlReportAsync()
    {
        await ExportReportAsync((store, path) => HtmlReportWriter.Write(store, _lastSoftware, path));
    }

    private async Task GenerateJsonReportAsync()
    {
        await ExportReportAsync((store, path) => JsonReportWriter.Write(store, path));
    }

    private async Task GenerateCsvReportAsync()
    {
        await ExportReportAsync((store, path) => CsvReportWriter.Write(store, path));
    }

    private void SaveSettings()
    {
        var path = Path.Combine(_configDir, "ui-settings.json");
        var settings = new UiSettings
        {
            EnableCveLookup = EnableCveLookup,
            GenerateHtml = GenerateHtml,
            GenerateJson = GenerateJson,
            EnableParallelAudit = EnableParallelAudit,
            ReportFolder = ReportFolder
        };

        settings.Save(path);

        if (!TrySaveAuditSettings(out var error))
        {
            StatusMessage = $"UI settings saved, but audit settings failed to save: {error}";
            return;
        }

        StatusMessage = "Settings saved locally to the application config folder.";
    }

    private async Task BrowseReportsFolderAsync()
    {
        if (App.Current?.ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime desktop || desktop.MainWindow is not Window window)
        {
            return;
        }

        var topLevel = TopLevel.GetTopLevel(window);
        var folders = await topLevel!.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Choose a report folder", AllowMultiple = false });
        var selected = folders.FirstOrDefault()?.Path.LocalPath;
        if (!string.IsNullOrWhiteSpace(selected))
        {
            ReportFolder = selected;
            StatusMessage = $"Report folder set to {selected}.";
        }
    }

    private void OpenReportsFolder()
    {
        var folder = string.IsNullOrWhiteSpace(ReportFolder) ? _reportDir : ReportFolder;
        Directory.CreateDirectory(folder);

        var startInfo = new ProcessStartInfo
        {
            FileName = folder,
            UseShellExecute = true
        };

        Process.Start(startInfo);
        StatusMessage = $"Opened {folder}.";
    }

    private async Task ExportReportAsync(Func<FindingStore, string, string> writer)
    {
        try
        {
            var path = EnsureReportFolder();
            writer(_store, path);
            StatusMessage = $"Report written to {path}.";
            RefreshReportHistory();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Report export failed: {ex.Message}";
        }

        await Task.CompletedTask;
    }

    private async Task ExportLogsAsync()
    {
        try
        {
            var folder = EnsureReportFolder();
            var file = Path.Combine(folder, $"perseus-audit-log-{DateTime.Now:yyyyMMdd-HHmmss}.log");
            File.WriteAllLines(file, Logs);
            StatusMessage = $"Logs exported to {file}";
            AddLog($"Logs exported: {file}");
        }
        catch (Exception ex)
        {
            StatusMessage = $"Log export failed: {ex.Message}";
        }

        await Task.CompletedTask;
    }

    private void RefreshFindings()
    {
        Findings.Clear();
        foreach (var finding in _store.All)
        {
            Findings.Add(finding);
        }

        RebuildFindingGroups();
        ApplyFindingsFilter();
    }

    private void UpdateSummary()
    {
        var findings = _store.All;
        OverallScore = RiskScorer.Score(findings);
        RiskLevel = RiskScorer.Level(OverallScore);
        CriticalCount = findings.Count(f => f.Severity == Severity.Critical);
        HighCount = findings.Count(f => f.Severity == Severity.High);
        MediumCount = findings.Count(f => f.Severity == Severity.Medium);
        LowCount = findings.Count(f => f.Severity == Severity.Low);
        WarningCount = findings.Count(f => f.Status == FindingStatus.Warning);
        InfoCount = findings.Count(f => f.Status == FindingStatus.Info);
        GoodCount = findings.Count(f => f.Status == FindingStatus.Good);

        UpdateDashboardSummary(findings);
    }

    private string EnsureReportFolder()
    {
        var folder = string.IsNullOrWhiteSpace(ReportFolder) ? _reportDir : ReportFolder;
        Directory.CreateDirectory(folder);
        ReportFolder = folder;
        return folder;
    }
}
