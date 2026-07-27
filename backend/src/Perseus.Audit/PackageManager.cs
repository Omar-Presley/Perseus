using System.Diagnostics;
using System.Text.Json;
using Perseus.Reporting;

namespace Perseus.Audit;

public sealed record UpgradeablePackage(string Name, string Id, string CurrentVersion, string AvailableVersion, string Source);

public sealed record CommandResult(bool Success, int ExitCode, string Output, string Error);

/// <summary>
/// The OS-dependent "what's out of date, and can we upgrade it" feature.
/// One method dispatches to the right tool per platform:
///   Windows -> winget
///   macOS   -> softwareupdate -l (OS-level updates) + brew outdated (3rd-party apps,
///              if Homebrew is present - softwareupdate alone doesn't cover apps like
///              winget/apt do, so this needs both to be a real functional match)
///   Linux   -> apt list --upgradable (Debian/Ubuntu family)
/// </summary>
public static class PackageManager
{
    public static async Task<CommandResult> RunAsync(string fileName, string arguments, int timeoutMs = 30000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            var completed = await Task.Run(() => process.WaitForExit(timeoutMs));
            if (!completed)
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
                return new CommandResult(false, -1, "", $"'{fileName}' timed out after {timeoutMs}ms");
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new CommandResult(process.ExitCode == 0, process.ExitCode, stdout, stderr);
        }
        catch (Exception ex)
        {
            return new CommandResult(false, -1, "", ex.Message);
        }
    }

    public static bool ToolAvailable(string toolName)
    {
        try
        {
            var checkCmd = OperatingSystem.IsWindows() ? "where" : "which";
            var psi = new ProcessStartInfo(checkCmd, toolName)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p!.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<List<UpgradeablePackage>> ListUpgradableAsync()
    {
        return PlatformHelper.Current switch
        {
            Platform.Windows => await ListWingetAsync(),
            Platform.MacOs => await ListMacAsync(),
            Platform.Linux => await ListAptAsync(),
            _ => new List<UpgradeablePackage>()
        };
    }

    public static async Task<CommandResult> UpgradeAsync(UpgradeablePackage package)
    {
        return PlatformHelper.Current switch
        {
            Platform.Windows => await RunAsync("winget",
                $"upgrade --id {package.Id} --silent --accept-package-agreements --accept-source-agreements"),
            Platform.MacOs when package.Source == "brew" => await RunAsync("brew", $"upgrade {package.Id}"),
            Platform.MacOs => new CommandResult(false, -1, "",
                "OS-level updates from softwareupdate must be applied via 'softwareupdate -i <label>' " +
                "(often requires a restart) - not automated here to avoid an unattended reboot."),
            Platform.Linux => await RunAsync("sudo", $"apt-get install --only-upgrade -y {package.Id}"),
            _ => new CommandResult(false, -1, "", "No package manager mapping for this platform.")
        };
    }

    // --- Windows: winget ---
    private static async Task<List<UpgradeablePackage>> ListWingetAsync()
    {
        var result = new List<UpgradeablePackage>();
        if (!ToolAvailable("winget")) return result;

        var cmd = await RunAsync("winget", "upgrade --accept-source-agreements");
        var lines = cmd.Output.Split('\n');

        var headerIndex = Array.FindIndex(lines, l => l.TrimStart().StartsWith("Name", StringComparison.Ordinal) && l.Contains("Id"));
        if (headerIndex < 0) return result;

        for (var i = headerIndex + 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('-')) continue;
            if (line.Contains("upgrades available", StringComparison.OrdinalIgnoreCase)) continue;

            var cols = System.Text.RegularExpressions.Regex.Split(line.Trim(), @"\s{2,}");
            if (cols.Length >= 4)
            {
                result.Add(new UpgradeablePackage(cols[0], cols[1], cols[2], cols[3], "winget"));
            }
        }
        return result;
    }

    // --- Linux: apt ---
    private static async Task<List<UpgradeablePackage>> ListAptAsync()
    {
        var result = new List<UpgradeablePackage>();
        if (!ToolAvailable("apt")) return result;

        var cmd = await RunAsync("apt", "list --upgradable");
        var lines = cmd.Output.Split('\n');

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("Listing...")) continue;

            // Format: package/repo,repo2 newVersion arch [upgradable from: oldVersion]
            var slashIndex = line.IndexOf('/');
            if (slashIndex < 0) continue;
            var name = line[..slashIndex];

            var fromMatch = System.Text.RegularExpressions.Regex.Match(line, @"upgradable from:\s*([^\]]+)\]");
            var newVersionMatch = System.Text.RegularExpressions.Regex.Match(line, @"^\S+\s+(\S+)\s+\S+");

            var oldVersion = fromMatch.Success ? fromMatch.Groups[1].Value.Trim() : "unknown";
            var newVersion = newVersionMatch.Success ? newVersionMatch.Groups[1].Value.Trim() : "unknown";

            result.Add(new UpgradeablePackage(name, name, oldVersion, newVersion, "apt"));
        }
        return result;
    }

    // --- macOS: softwareupdate (OS) + brew (3rd-party apps) ---
    private static async Task<List<UpgradeablePackage>> ListMacAsync()
    {
        var result = new List<UpgradeablePackage>();

        // OS-level updates
        var suCmd = await RunAsync("softwareupdate", "-l");
        foreach (var line in suCmd.Output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("* Label:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("*", StringComparison.Ordinal))
            {
                var label = trimmed.TrimStart('*', ' ').Replace("Label:", "").Trim();
                if (!string.IsNullOrWhiteSpace(label))
                {
                    result.Add(new UpgradeablePackage(label, label, "installed", "available", "softwareupdate"));
                }
            }
        }

        // Third-party apps via Homebrew, if present - this is the piece that actually
        // matches what winget/apt do for arbitrary installed software.
        if (ToolAvailable("brew"))
        {
            var brewCmd = await RunAsync("brew", "outdated --json=v2");
            try
            {
                using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(brewCmd.Output) ? "{}" : brewCmd.Output);
                if (doc.RootElement.TryGetProperty("formulae", out var formulae))
                {
                    foreach (var f in formulae.EnumerateArray())
                    {
                        var name = f.GetProperty("name").GetString() ?? "unknown";
                        var installed = f.GetProperty("installed_versions").EnumerateArray().FirstOrDefault().GetString() ?? "unknown";
                        var current = f.GetProperty("current_version").GetString() ?? "unknown";
                        result.Add(new UpgradeablePackage(name, name, installed, current, "brew"));
                    }
                }
            }
            catch
            {
                // brew not installed/outdated output not JSON in this brew version - skip gracefully
            }
        }

        return result;
    }
}
