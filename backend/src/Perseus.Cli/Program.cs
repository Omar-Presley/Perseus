using Perseus.Audit;
using Perseus.Cve;
using Perseus.Network;
using Perseus.Reporting;

var baseDir = AppContext.BaseDirectory;
// config/reports/logs sit next to the executable, whether run via
// 'dotnet run' (bin/Debug/net8.0/) or a published, self-contained build.
var configDir = Path.Combine(baseDir, "config");
var reportDir = Path.Combine(baseDir, "reports");
var logDir = Path.Combine(baseDir, "logs");
Directory.CreateDirectory(reportDir);
Directory.CreateDirectory(logDir);

ConsoleUi.NoBanner = args.Contains("--no-banner");

var settings = ConfigLoader.LoadSettings(configDir);
var signatures = ConfigLoader.LoadSignatures(configDir);

ICheckProvider provider = PlatformHelper.Current switch
{
    Platform.Windows => new WindowsCheckProvider(settings, signatures),
    Platform.Linux => new LinuxCheckProvider(settings, signatures),
    Platform.MacOs => new MacCheckProvider(settings, signatures),
    _ => throw new PlatformNotSupportedException(
        $"No check provider for platform '{PlatformHelper.Current}'. " +
        "Supported: Windows, Linux, macOS.")
};

var store = new FindingStore();
List<SoftwareItem> lastSoftware = new();

async Task FullScanAsync()
{
    store.Clear();
    foreach (var check in provider.Checks)
    {
        await check.Run(store);
    }
    await PortScanner.RunCheckAsync(store, settings.RiskyPorts);
    lastSoftware = await provider.GetSoftwareInventoryAsync(store);
    ConsoleUi.ShowSummary(store);
}

void ShowMenu()
{
    ConsoleUi.ShowBanner();
    Console.WriteLine($"  Platform: {provider.PlatformLabel}\n");

    for (var i = 0; i < provider.Checks.Count; i++)
    {
        Console.WriteLine($"  [{i + 1,2}] {provider.Checks[i].Label}");
    }

    var n = provider.Checks.Count;
    Console.WriteLine($"  [{n + 1,2}] Open/Listening Ports (with process & service attribution)");
    Console.WriteLine($"  [{n + 2,2}] Installed Software Inventory");
    Console.WriteLine($"  [{n + 3,2}] CVE Lookup - CPE version-matched (requires internet, run software inventory first)");
    Console.WriteLine($"  [{n + 4,2}] FULL SCAN (all read-only checks above)");
    Console.WriteLine($"  [{n + 5,2}] Export HTML Report");
    Console.WriteLine($"  [{n + 6,2}] Export JSON Report");
    Console.WriteLine($"  [{n + 7,2}] Export CSV Report");
    Console.WriteLine($"  [{n + 8,2}] Show Last Summary");
    Console.Write($"  [{n + 9,2}] Upgrade Outdated Software ");
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("(modifies your system)");
    Console.ResetColor();
    Console.WriteLine("  [ 0] Exit");
    ConsoleUi.ShowLine();
    Console.Write("  Selection: ");
}

string? choice;
do
{
    ShowMenu();
    choice = Console.ReadLine();
    var n = provider.Checks.Count;

    if (int.TryParse(choice, out var selection))
    {
        if (selection >= 1 && selection <= n)
        {
            await provider.Checks[selection - 1].Run(store);
        }
        else if (selection == n + 1)
        {
            await PortScanner.RunCheckAsync(store, settings.RiskyPorts);
        }
        else if (selection == n + 2)
        {
            lastSoftware = await provider.GetSoftwareInventoryAsync(store);
        }
        else if (selection == n + 3)
        {
            if (lastSoftware.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n  [!] Run option {n + 2} first to build the software inventory.");
                Console.ResetColor();
            }
            else
            {
                await CveLookup.RunAsync(store, lastSoftware, settings, signatures);
            }
        }
        else if (selection == n + 4)
        {
            await FullScanAsync();
        }
        else if (selection == n + 5)
        {
            HtmlReportWriter.Write(store, lastSoftware, reportDir);
        }
        else if (selection == n + 6)
        {
            JsonReportWriter.Write(store, reportDir);
        }
        else if (selection == n + 7)
        {
            CsvReportWriter.Write(store, reportDir);
        }
        else if (selection == n + 8)
        {
            ConsoleUi.ShowSummary(store);
        }
        else if (selection == n + 9)
        {
            await UpgradeMenu.RunAsync(store);
        }
        else if (selection != 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n  Invalid selection.");
            Console.ResetColor();
        }
    }
    else if (choice != "0")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\n  Invalid selection.");
        Console.ResetColor();
    }

    if (choice != "0")
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("\n  Press Enter to return to the menu...");
        Console.ResetColor();
        Console.ReadLine();
    }
} while (choice != "0");

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("\n  Goodbye.");
Console.ResetColor();
