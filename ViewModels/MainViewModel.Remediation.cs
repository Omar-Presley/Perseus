using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Perseus.Audit;
using Perseus.Reporting;

namespace Perseus.ViewModels;

public sealed class UpgradeCandidateViewModel : ViewModelBase
{
    public UpgradeCandidateViewModel(UpgradeablePackage package, bool canSelect)
    {
        Package = package;
        CanSelect = canSelect;
        _isSelected = canSelect;
        _statusText = canSelect ? "Pending" : "Not automatable on this platform";
    }

    public UpgradeablePackage Package { get; }
    public bool CanSelect { get; }

    private bool _isSelected;
    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    private string _statusText;
    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    private bool _isInProgress;
    public bool IsInProgress
    {
        get => _isInProgress;
        set => SetProperty(ref _isInProgress, value);
    }

    private bool? _succeeded;
    public bool? Succeeded
    {
        get => _succeeded;
        set => SetProperty(ref _succeeded, value);
    }
}

public partial class MainViewModel
{
    private bool _isScanningUpgrades;
    private bool _isUpgrading;
    private bool _isConfirmingUpgrade;
    private string _upgradeConfirmationMessage = string.Empty;

    public ObservableCollection<UpgradeCandidateViewModel> UpgradeCandidates { get; } = new();

    public AsyncRelayCommand ScanUpgradesCommand { get; private set; } = null!;
    public RelayCommand UpgradeSelectedCommand { get; private set; } = null!;
    public AsyncRelayCommand ConfirmUpgradeCommand { get; private set; } = null!;
    public RelayCommand CancelUpgradeCommand { get; private set; } = null!;

    public bool IsScanningUpgrades
    {
        get => _isScanningUpgrades;
        set => SetProperty(ref _isScanningUpgrades, value);
    }

    public bool IsUpgrading
    {
        get => _isUpgrading;
        set => SetProperty(ref _isUpgrading, value);
    }

    public bool IsConfirmingUpgrade
    {
        get => _isConfirmingUpgrade;
        set => SetProperty(ref _isConfirmingUpgrade, value);
    }

    public string UpgradeConfirmationMessage
    {
        get => _upgradeConfirmationMessage;
        set => SetProperty(ref _upgradeConfirmationMessage, value);
    }

    private void InitializeRemediationState()
    {
        ScanUpgradesCommand = new AsyncRelayCommand(async _ => await ScanUpgradesAsync());
        UpgradeSelectedCommand = new RelayCommand(_ => BeginUpgradeConfirmation());
        ConfirmUpgradeCommand = new AsyncRelayCommand(async _ => await ConfirmUpgradeAsync());
        CancelUpgradeCommand = new RelayCommand(_ =>
        {
            IsConfirmingUpgrade = false;
            UpgradeConfirmationMessage = string.Empty;
        });
    }

    private async Task ScanUpgradesAsync()
    {
        if (IsScanningUpgrades || IsUpgrading) return;

        IsScanningUpgrades = true;
        StatusMessage = "Scanning for available package upgrades...";
        AddLog("Scanning for available package upgrades");

        try
        {
            var upgrades = await PackageManager.ListUpgradableAsync();
            UpgradeCandidates.Clear();

            foreach (var package in upgrades)
            {
                // softwareupdate (macOS OS-level updates) is deliberately refused by
                // PackageManager.UpgradeAsync to avoid an unattended reboot - never
                // present it as something the user can select and run here.
                var canSelect = package.Source != "softwareupdate";
                UpgradeCandidates.Add(new UpgradeCandidateViewModel(package, canSelect));
            }

            StatusMessage = upgrades.Count > 0
                ? $"Found {upgrades.Count} available upgrade(s)."
                : "No upgrades detected - check the Audit Log; this can also mean no supported package manager was found.";
            AddLog($"Upgrade scan complete: {upgrades.Count} candidate(s)");
        }
        catch (Exception ex)
        {
            StatusMessage = $"Upgrade scan failed: {ex.Message}";
            AddLog($"Upgrade scan failed: {ex.Message}");
        }
        finally
        {
            IsScanningUpgrades = false;
        }
    }

    private void BeginUpgradeConfirmation()
    {
        var selected = UpgradeCandidates.Where(c => c.CanSelect && c.IsSelected).ToList();
        if (selected.Count == 0)
        {
            StatusMessage = "Select at least one upgradeable package first.";
            return;
        }

        UpgradeConfirmationMessage =
            $"This will run the {PlatformHelper.Current} package manager and MODIFY installed software for {selected.Count} package(s):\n" +
            string.Join("\n", selected.Select(c => $"  - {c.Package.Name} ({c.Package.CurrentVersion} -> {c.Package.AvailableVersion})"));
        IsConfirmingUpgrade = true;
    }

    private async Task ConfirmUpgradeAsync()
    {
        if (IsUpgrading) return;

        IsConfirmingUpgrade = false;
        var targets = UpgradeCandidates.Where(c => c.CanSelect && c.IsSelected).ToList();
        if (targets.Count == 0) return;

        IsUpgrading = true;
        StatusMessage = "Applying selected upgrades...";
        AddLog($"Starting upgrade of {targets.Count} package(s)");

        // Sequential, matching UpgradeMenu.cs - concurrent package-manager
        // invocations can lock the same package database.
        foreach (var candidate in targets)
        {
            candidate.IsInProgress = true;
            candidate.StatusText = "Upgrading...";
            AddLog($"Upgrading {candidate.Package.Name} ({candidate.Package.CurrentVersion} -> {candidate.Package.AvailableVersion}) via {candidate.Package.Source}");

            var result = await PackageManager.UpgradeAsync(candidate.Package);

            candidate.IsInProgress = false;
            candidate.Succeeded = result.Success;

            if (result.Success)
            {
                candidate.StatusText = "Upgraded successfully";
                AddLog($"{candidate.Package.Name} upgraded successfully");
                _store.Add("Remediation", $"Upgraded: {candidate.Package.Name}", FindingStatus.Good,
                    $"{candidate.Package.CurrentVersion} -> {candidate.Package.AvailableVersion} via {candidate.Package.Source}.");
            }
            else
            {
                candidate.StatusText = $"Failed: {result.Error}";
                AddLog($"{candidate.Package.Name} upgrade did not complete: {result.Error}");
                _store.Add("Remediation", $"Upgrade Attempted: {candidate.Package.Name}", FindingStatus.Warning,
                    $"{candidate.Package.Source} reported: {result.Error}",
                    $"Run the upgrade for '{candidate.Package.Id}' manually via {candidate.Package.Source} and review the output.",
                    Severity.Low);
            }
        }

        RefreshFindings();
        UpdateSummary();
        StatusMessage = "Upgrade run finished. Review results below and in Findings.";
        AddLog("Upgrade run finished");
        IsUpgrading = false;
    }
}
