using Perseus.Reporting;

namespace Perseus.Audit;

/// <summary>
/// Cross-platform version of the winget upgrade menu: same interaction
/// model (show list, require explicit selection, log outcomes as
/// Remediation findings), dispatched per-OS via PackageManager. This is
/// still the only action in the whole tool that changes anything on the
/// system - every check elsewhere only reads.
/// </summary>
public static class UpgradeMenu
{
    public static async Task RunAsync(FindingStore store)
    {
        var platform = PlatformHelper.Current;
        Console.WriteLine($"\n[*] Checking for available upgrades ({platform})...");

        var upgrades = await PackageManager.ListUpgradableAsync();
        if (upgrades.Count == 0)
        {
            ConsoleUi.WriteStatus("OK", "No upgrades available (or no supported package manager found)", ConsoleColor.Green);
            return;
        }

        ConsoleUi.ShowLine();
        Console.WriteLine("  Outdated software detected:");
        for (var i = 0; i < upgrades.Count; i++)
        {
            var u = upgrades[i];
            Console.WriteLine($"  [{i + 1,2}] {u.Name,-28} ({u.Source,-12}) {u.CurrentVersion,-14} -> {u.AvailableVersion}");
        }
        ConsoleUi.ShowLine();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  This runs the {platform} package manager and WILL MODIFY installed software.");
        Console.ResetColor();
        Console.Write("  Enter numbers to upgrade (e.g. 1,3,5), 'all', or press Enter to skip: ");
        var selection = (Console.ReadLine() ?? "").Trim();

        if (string.IsNullOrEmpty(selection))
        {
            Console.WriteLine("  Skipped - no changes made.");
            return;
        }

        List<UpgradeablePackage> targets;
        if (selection.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            targets = upgrades;
        }
        else
        {
            var indices = selection.Split(',')
                .Select(s => s.Trim())
                .Where(s => int.TryParse(s, out _))
                .Select(s => int.Parse(s) - 1)
                .Where(i => i >= 0 && i < upgrades.Count);
            targets = indices.Select(i => upgrades[i]).ToList();
        }

        if (targets.Count == 0)
        {
            Console.WriteLine("  No valid selections - no changes made.");
            return;
        }

        foreach (var t in targets)
        {
            Console.WriteLine($"\n  Upgrading {t.Name} ({t.CurrentVersion} -> {t.AvailableVersion}) via {t.Source}...");
            var result = await PackageManager.UpgradeAsync(t);

            if (result.Success)
            {
                ConsoleUi.WriteStatus("OK", $"{t.Name} upgraded successfully", ConsoleColor.Green);
                store.Add("Remediation", $"Upgraded: {t.Name}", FindingStatus.Good,
                    $"{t.CurrentVersion} -> {t.AvailableVersion} via {t.Source}.");
            }
            else
            {
                ConsoleUi.WriteStatus("!", $"{t.Name} upgrade did not complete: {result.Error}", ConsoleColor.Yellow);
                store.Add("Remediation", $"Upgrade Attempted: {t.Name}", FindingStatus.Warning,
                    $"{t.Source} reported: {result.Error}",
                    $"Run the upgrade for '{t.Id}' manually via {t.Source} and review the output.", Severity.Low);
            }
        }
    }
}
