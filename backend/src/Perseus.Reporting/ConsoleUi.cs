using System.Runtime.InteropServices;

namespace Perseus.Reporting;

public static class ConsoleUi
{
    public static bool NoBanner { get; set; }

    public static void ShowLine() => Console.WriteLine(new string('-', 70));

    public static void WriteStatus(string symbol, string text, ConsoleColor color = ConsoleColor.White)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write($"  [{symbol}] ");
        Console.ForegroundColor = previous;
        Console.WriteLine(text);
    }

    public static void ShowBanner()
    {
        if (NoBanner) return;
        try { Console.Clear(); } catch { /* not all terminals support this */ }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
██████╗ ███████╗██████╗ ███████╗███████╗██╗   ██╗███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝
██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║   ██║███████╗
██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║   ██║╚════██║
██║     ███████╗██║  ██║███████║███████╗╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝

 Proactive Endpoint Review and Security Evaluation
                Utility Suite

Version 2.0 (C#/.NET, cross-platform core)");
        Console.ResetColor();
        ShowLine();

        var elevated = PlatformHelper.IsElevated();
        Console.ForegroundColor = elevated ? ConsoleColor.Green : ConsoleColor.Yellow;
        Console.WriteLine(elevated
            ? "  [i] Running with elevated privileges."
            : "  [!] Not running elevated - some checks will be limited.");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Host: {Environment.MachineName}   User: {Environment.UserName}   " +
                           $"Platform: {PlatformHelper.Current}   Date: {DateTime.Now}");
        Console.WriteLine($"  Runtime: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})");
        Console.ResetColor();
        ShowLine();
    }

    public static void ShowSummary(FindingStore store)
    {
        var score = RiskScorer.Score(store.All);
        var level = RiskScorer.Level(score);
        var levelColor = level switch
        {
            "LOW" => ConsoleColor.Green,
            "MEDIUM" => ConsoleColor.Yellow,
            _ => ConsoleColor.Red
        };

        ShowLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  AUDIT SUMMARY");
        Console.ResetColor();
        ShowLine();

        var bad = store.CountByStatus(FindingStatus.Bad);
        var warn = store.CountByStatus(FindingStatus.Warning);
        var good = store.CountByStatus(FindingStatus.Good);

        Console.Write("  Findings: ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{bad} Bad ");
        Console.ResetColor();
        Console.Write("| ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{warn} Warning ");
        Console.ResetColor();
        Console.Write("| ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"{good} Good");
        Console.ResetColor();

        const int barLength = 20;
        var filled = (int)Math.Round(score / 100.0 * barLength);
        var bar = new string('#', filled).PadRight(barLength, '.');

        Console.ForegroundColor = levelColor;
        Console.WriteLine($"\n  Risk Score : [{bar}] {score} / 100");
        Console.WriteLine($"  Risk Level : {level}");
        Console.ResetColor();
        ShowLine();
    }
}
