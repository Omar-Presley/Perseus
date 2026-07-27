using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using Perseus.Audit;
using Perseus.Models;

namespace Perseus.ViewModels;

public sealed class RiskyPortEntry
{
    public string Port { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
}

public partial class MainViewModel
{
    private int _maxCveTargets;
    private string _nvdApiKeySetting = string.Empty;
    private int _nvdDelayMsSetting;
    private int _updateStalenessDaysSetting;
    private int _maxAdminAccountsSetting;
    private string _anthropicApiKeySetting = string.Empty;

    public ObservableCollection<RiskyPortEntry> RiskyPorts { get; } = new();

    public RelayCommand AddRiskyPortCommand { get; private set; } = null!;
    public RelayCommand RemoveRiskyPortCommand { get; private set; } = null!;
    public RelayCommand RestoreDefaultSettingsCommand { get; private set; } = null!;
    public RelayCommand SaveAnthropicKeyCommand { get; private set; } = null!;

    public string AnthropicApiKeySetting
    {
        get => _anthropicApiKeySetting;
        set => SetProperty(ref _anthropicApiKeySetting, value);
    }

    public int MaxCveTargets
    {
        get => _maxCveTargets;
        set => SetProperty(ref _maxCveTargets, Math.Max(0, value));
    }

    public string NvdApiKeySetting
    {
        get => _nvdApiKeySetting;
        set => SetProperty(ref _nvdApiKeySetting, value);
    }

    // NVD's public rate limit is shared across all callers - floor this so a user
    // can't accidentally set a delay low enough to get the app rate-limited.
    private const int MinNvdDelayMs = 600;

    public int NvdDelayMsSetting
    {
        get => _nvdDelayMsSetting;
        set => SetProperty(ref _nvdDelayMsSetting, Math.Max(MinNvdDelayMs, value));
    }

    public int UpdateStalenessDaysSetting
    {
        get => _updateStalenessDaysSetting;
        set => SetProperty(ref _updateStalenessDaysSetting, Math.Max(0, value));
    }

    public int MaxAdminAccountsSetting
    {
        get => _maxAdminAccountsSetting;
        set => SetProperty(ref _maxAdminAccountsSetting, Math.Max(0, value));
    }

    private void InitializeSettingsState()
    {
        LoadAuditSettingsIntoFields();
        AnthropicApiKeySetting = AnthropicKeyStore.Load(AnthropicKeyPath);
        UpdateHasAnthropicApiKey();

        AddRiskyPortCommand = new RelayCommand(_ => RiskyPorts.Add(new RiskyPortEntry()));
        RemoveRiskyPortCommand = new RelayCommand(p =>
        {
            if (p is RiskyPortEntry entry) RiskyPorts.Remove(entry);
        });
        RestoreDefaultSettingsCommand = new RelayCommand(_ =>
        {
            _settings = new AuditSettings();
            LoadAuditSettingsIntoFields();
            StatusMessage = "Audit settings reset to defaults locally. Click Save Settings to persist.";
        });
        SaveAnthropicKeyCommand = new RelayCommand(_ =>
        {
            AnthropicKeyStore.Save(AnthropicKeyPath, AnthropicApiKeySetting);
            UpdateHasAnthropicApiKey();
            StatusMessage = "Anthropic API key saved.";
        });
    }

    private string AnthropicKeyPath => Path.Combine(_configDir, "anthropic.key");

    private void LoadAuditSettingsIntoFields()
    {
        MaxCveTargets = _settings.MaxCveTargets;
        NvdApiKeySetting = _settings.NvdApiKey;
        NvdDelayMsSetting = _settings.NvdDelayMs;
        UpdateStalenessDaysSetting = _settings.UpdateStalenessDays;
        MaxAdminAccountsSetting = _settings.MaxAdminAccounts;

        RiskyPorts.Clear();
        foreach (var (port, label) in _settings.RiskyPorts)
        {
            RiskyPorts.Add(new RiskyPortEntry { Port = port, Label = label });
        }
    }

    private bool TrySaveAuditSettings(out string? error)
    {
        var rebuilt = new System.Collections.Generic.Dictionary<string, string>();
        foreach (var entry in RiskyPorts)
        {
            var port = entry.Port.Trim();
            if (!int.TryParse(port, out _))
            {
                error = $"Risky port '{port}' is not a valid port number.";
                return false;
            }

            if (!rebuilt.TryAdd(port, entry.Label.Trim()))
            {
                error = $"Duplicate risky port entry: {port}.";
                return false;
            }
        }

        _settings.RiskyPorts = rebuilt;
        _settings.MaxCveTargets = MaxCveTargets;
        _settings.NvdApiKey = NvdApiKeySetting;
        _settings.NvdDelayMs = NvdDelayMsSetting;
        _settings.UpdateStalenessDays = UpdateStalenessDaysSetting;
        _settings.MaxAdminAccounts = MaxAdminAccountsSetting;

        try
        {
            ConfigLoader.SaveSettings(_configDir, _settings);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
