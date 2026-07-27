using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Perseus.Network;

namespace Perseus.ViewModels;

public sealed class PortRowViewModel
{
    public PortRowViewModel(ListeningPort port, bool isRisky, string? riskLabel)
    {
        Port = port.Port;
        Pid = port.Pid;
        ProcessName = port.ProcessName;
        Path = port.Path;
        ServiceName = port.ServiceName;
        IsRisky = isRisky;
        RiskLabel = riskLabel;
    }

    public int Port { get; }
    public int? Pid { get; }
    public string ProcessName { get; }
    public string? Path { get; }
    public string? ServiceName { get; }
    public bool IsRisky { get; }
    public string? RiskLabel { get; }
}

public partial class MainViewModel
{
    private readonly List<ListeningPort> _allPorts = new();

    private string _networkFilterText = string.Empty;
    private int _totalPortsCount;
    private int _riskyPortsCount;
    private int _distinctProcessCount;

    public ObservableCollection<PortRowViewModel> FilteredListeningPorts { get; } = new();

    public string NetworkFilterText
    {
        get => _networkFilterText;
        set { SetProperty(ref _networkFilterText, value); ApplyNetworkFilter(); }
    }

    public int TotalPortsCount
    {
        get => _totalPortsCount;
        set => SetProperty(ref _totalPortsCount, value);
    }

    public int RiskyPortsCount
    {
        get => _riskyPortsCount;
        set => SetProperty(ref _riskyPortsCount, value);
    }

    public int DistinctProcessCount
    {
        get => _distinctProcessCount;
        set => SetProperty(ref _distinctProcessCount, value);
    }

    private void InitializeNetworkState()
    {
        // Nothing to wire beyond the collection above; populated on first scan.
    }

    private void ApplyPortScanResults(List<ListeningPort> ports)
    {
        _allPorts.Clear();
        _allPorts.AddRange(ports);

        TotalPortsCount = ports.Count;
        RiskyPortsCount = ports.Count(IsRiskyPort);
        DistinctProcessCount = ports.Select(p => p.ProcessName).Distinct().Count();

        ApplyNetworkFilter();
    }

    private bool IsRiskyPort(ListeningPort port) => _settings.RiskyPorts.ContainsKey(port.Port.ToString());

    private void ApplyNetworkFilter()
    {
        IEnumerable<ListeningPort> query = _allPorts;

        if (!string.IsNullOrWhiteSpace(NetworkFilterText))
        {
            var text = NetworkFilterText.Trim();
            query = query.Where(p =>
                p.ProcessName.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                p.Port.ToString().Contains(text, StringComparison.OrdinalIgnoreCase) ||
                (p.ServiceName?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        FilteredListeningPorts.Clear();
        foreach (var port in query.OrderBy(p => p.Port))
        {
            var risky = _settings.RiskyPorts.TryGetValue(port.Port.ToString(), out var label);
            FilteredListeningPorts.Add(new PortRowViewModel(port, risky, label));
        }
    }
}
