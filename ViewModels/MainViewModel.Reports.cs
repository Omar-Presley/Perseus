using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Perseus.ViewModels;

public sealed record ReportFileInfo(string FileName, string FullPath, string Format, long SizeKb, DateTime CreatedAt);

public partial class MainViewModel
{
    public ObservableCollection<ReportFileInfo> ReportHistory { get; } = new();

    public RelayCommand RefreshReportsCommand { get; private set; } = null!;
    public AsyncRelayCommand GenerateFullReportSetCommand { get; private set; } = null!;
    public RelayCommand OpenReportCommand { get; private set; } = null!;

    private void InitializeReportsState()
    {
        RefreshReportsCommand = new RelayCommand(_ => RefreshReportHistory());
        GenerateFullReportSetCommand = new AsyncRelayCommand(async _ => await GenerateFullReportSetAsync());
        OpenReportCommand = new RelayCommand(p => OpenReportFile(p as ReportFileInfo));

        RefreshReportHistory();
    }

    private async Task GenerateFullReportSetAsync()
    {
        await GenerateHtmlReportAsync();
        await GenerateJsonReportAsync();
        await GenerateCsvReportAsync();
        StatusMessage = "Full report set generated (HTML, JSON, CSV).";
    }

    private void OpenReportFile(ReportFileInfo? report)
    {
        if (report is null) return;

        try
        {
            Process.Start(new ProcessStartInfo { FileName = report.FullPath, UseShellExecute = true });
            StatusMessage = $"Opened {report.FileName}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Unable to open {report.FileName}: {ex.Message}";
        }
    }

    private void RefreshReportHistory()
    {
        ReportHistory.Clear();

        var folder = string.IsNullOrWhiteSpace(ReportFolder) ? _reportDir : ReportFolder;
        if (!Directory.Exists(folder)) return;

        var files = Directory.GetFiles(folder, "Perseus_AuditReport_*.*")
            .Select(f => new FileInfo(f))
            .OrderByDescending(f => f.LastWriteTime);

        foreach (var file in files)
        {
            ReportHistory.Add(new ReportFileInfo(
                file.Name,
                file.FullName,
                file.Extension.TrimStart('.').ToUpperInvariant(),
                file.Length / 1024,
                file.LastWriteTime));
        }
    }
}
