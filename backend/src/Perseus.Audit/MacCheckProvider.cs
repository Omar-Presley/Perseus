using Perseus.Reporting;

namespace Perseus.Audit;

/// <summary>
/// macOS equivalents of the Windows checks, using standard Apple
/// command-line tools (fdesetup, spctl, csrutil, the ApplicationFirewall
/// helper, dscl). These are documented, long-stable commands referenced in
/// Apple's own admin guides and the CIS macOS Benchmark - but unlike the
/// Linux provider, none of this has actually been run against a real Mac,
/// because this sandbox doesn't have one. Treat this file as "should be
/// correct based on documented command behavior," not "verified."
/// </summary>
public sealed class MacCheckProvider : ICheckProvider
{
    private readonly AuditSettings _settings;
    private readonly AuditSignatures _signatures;

    public MacCheckProvider(AuditSettings settings, AuditSignatures signatures)
    {
        _settings = settings;
        _signatures = signatures;
    }

    public string PlatformLabel => "macOS";

    public IReadOnlyList<MenuCheck> Checks => new List<MenuCheck>
    {
        new("FileVault (Disk Encryption)", RunFileVaultCheckAsync),
        new("Gatekeeper", RunGatekeeperCheckAsync),
        new("System Integrity Protection (SIP)", RunSipCheckAsync),
        new("Application Firewall", RunFirewallCheckAsync),
        new("Admin Group Members", RunAdminGroupCheckAsync),
    };

    // ------------------------------------------------------------------
    public async Task RunFileVaultCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking FileVault status...");
        var result = await PackageManager.RunAsync("fdesetup", "status");
        if (result.Output.Contains("FileVault is On", StringComparison.OrdinalIgnoreCase))
        {
            ConsoleUi.WriteStatus("OK", "FileVault is On", ConsoleColor.Green);
        }
        else
        {
            store.Add("DiskEncryption", "FileVault", FindingStatus.Bad,
                "FileVault is Off.", "Enable FileVault for full-disk encryption.", Severity.High);
            ConsoleUi.WriteStatus("X", "FileVault is Off", ConsoleColor.Red);
        }
    }

    // ------------------------------------------------------------------
    public async Task RunGatekeeperCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Gatekeeper status...");
        var result = await PackageManager.RunAsync("spctl", "--status");
        if (result.Output.Contains("assessments enabled", StringComparison.OrdinalIgnoreCase))
        {
            ConsoleUi.WriteStatus("OK", "Gatekeeper enabled", ConsoleColor.Green);
        }
        else
        {
            store.Add("ModernSecurity", "Gatekeeper", FindingStatus.Bad,
                "Gatekeeper assessments are disabled.", "Re-enable Gatekeeper ('spctl --master-enable').", Severity.High);
            ConsoleUi.WriteStatus("X", "Gatekeeper disabled", ConsoleColor.Red);
        }
    }

    // ------------------------------------------------------------------
    public async Task RunSipCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking System Integrity Protection (SIP)...");
        var result = await PackageManager.RunAsync("csrutil", "status");
        if (result.Output.Contains("enabled", StringComparison.OrdinalIgnoreCase))
        {
            ConsoleUi.WriteStatus("OK", "SIP enabled", ConsoleColor.Green);
        }
        else
        {
            store.Add("ModernSecurity", "SIP", FindingStatus.Bad,
                "System Integrity Protection is disabled.",
                "Re-enable SIP (requires booting into Recovery Mode: 'csrutil enable').", Severity.Critical);
            ConsoleUi.WriteStatus("X", "SIP disabled", ConsoleColor.Red);
        }
    }

    // ------------------------------------------------------------------
    public async Task RunFirewallCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Application Firewall...");
        var result = await PackageManager.RunAsync(
            "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate");

        if (result.Output.Contains("enabled", StringComparison.OrdinalIgnoreCase))
        {
            ConsoleUi.WriteStatus("OK", "Application Firewall enabled", ConsoleColor.Green);
        }
        else
        {
            store.Add("Firewall", "Application Firewall", FindingStatus.Bad,
                "Application Firewall is disabled.", "Enable the firewall in System Settings > Network > Firewall.",
                Severity.High, internetExposed: true);
            ConsoleUi.WriteStatus("X", "Application Firewall disabled", ConsoleColor.Red);
        }
    }

    // ------------------------------------------------------------------
    public async Task RunAdminGroupCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking admin group membership...");
        var result = await PackageManager.RunAsync("dscl", ". -read /Groups/admin GroupMembership");
        var line = result.Output.Split('\n').FirstOrDefault(l => l.StartsWith("GroupMembership:", StringComparison.OrdinalIgnoreCase));
        if (line is null)
        {
            store.Add("Accounts", "Admin Group Members", FindingStatus.Unknown, "Could not read admin group membership.");
            return;
        }

        var members = line.Replace("GroupMembership:", "").Trim()
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        store.Add("Accounts", "Admin Group Members", FindingStatus.Info, string.Join(", ", members));
        ConsoleUi.WriteStatus("i", $"admin group has {members.Length} member(s)", ConsoleColor.Cyan);

        if (members.Length > _settings.MaxAdminAccounts)
        {
            store.Add("Accounts", "Excess Admins", FindingStatus.Warning,
                $"{members.Length} accounts are in the admin group (threshold: {_settings.MaxAdminAccounts}).",
                "Apply least-privilege - remove unnecessary admin group members.", Severity.Medium);
            ConsoleUi.WriteStatus("!", $"{members.Length} accounts hold admin rights (review recommended)", ConsoleColor.Yellow);
        }
    }

    // ------------------------------------------------------------------
    // Software inventory - Homebrew (if present) + /Applications listing
    // ------------------------------------------------------------------
    public async Task<List<SoftwareItem>> GetSoftwareInventoryAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Enumerating installed software...");
        var software = new List<SoftwareItem>();

        if (PackageManager.ToolAvailable("brew"))
        {
            var brewResult = await PackageManager.RunAsync("brew", "list --versions");
            foreach (var line in brewResult.Output.Split('\n'))
            {
                var parts = line.Trim().Split(' ', 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[0]))
                {
                    software.Add(new SoftwareItem(parts[0], parts[1], null, "brew"));
                }
            }
        }

        const string appsDir = "/Applications";
        if (Directory.Exists(appsDir))
        {
            foreach (var appPath in Directory.GetDirectories(appsDir, "*.app"))
            {
                var name = Path.GetFileNameWithoutExtension(appPath);
                // A real version read would parse Info.plist (CFBundleShortVersionString);
                // skipped here since plist parsing needs a plist library this project
                // doesn't currently reference - version shows as "unknown" for /Applications
                // entries not also tracked by Homebrew.
                if (!software.Any(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    software.Add(new SoftwareItem(name, "unknown", null, "/Applications"));
                }
            }
        }

        ConsoleUi.WriteStatus("i", $"{software.Count} application(s) found", ConsoleColor.Cyan);
        store.Add("Software", "Installed Applications", FindingStatus.Info, $"{software.Count} applications enumerated.");

        foreach (var item in software)
        {
            if (_signatures.SoftwareWatchlist.Any(w => item.Name.Contains(w, StringComparison.OrdinalIgnoreCase)))
            {
                store.Add("Software", item.Name, FindingStatus.Warning,
                    $"Version {item.Version} - historically frequent CVE target.",
                    "Verify this is the latest version and patch/remove if unused.", Severity.Low);
            }
        }

        return software;
    }
}
