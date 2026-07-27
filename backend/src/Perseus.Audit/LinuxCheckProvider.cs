using System.Text.Json;
using System.Text.RegularExpressions;
using Perseus.Reporting;

namespace Perseus.Audit;

/// <summary>
/// Linux equivalents of the Windows checks, targeting the Debian/Ubuntu
/// family (matching "apt" named in the request). RHEL/Arch-family
/// equivalents (dnf/pacman, firewalld-only, SELinux-only) are noted inline
/// where the logic would need to branch further - not implemented here to
/// avoid guessing at commands I have no way to verify from this sandbox.
/// </summary>
public sealed class LinuxCheckProvider : ICheckProvider
{
    private readonly AuditSettings _settings;
    private readonly AuditSignatures _signatures;

    public LinuxCheckProvider(AuditSettings settings, AuditSignatures signatures)
    {
        _settings = settings;
        _signatures = signatures;
    }

    public string PlatformLabel => "Linux";

    public IReadOnlyList<MenuCheck> Checks => new List<MenuCheck>
    {
        new("SSH Root Login", RunSshRootLoginCheckAsync),
        new("Firewall (ufw/firewalld/iptables)", RunFirewallCheckAsync),
        new("Disk Encryption (LUKS)", RunDiskEncryptionCheckAsync),
        new("Sudo Group Members", RunSudoGroupCheckAsync),
        new("Mandatory Access Control (AppArmor/SELinux)", RunMacCheckAsync),
        new("Unattended Upgrades", RunUnattendedUpgradesCheckAsync),
        new("Secure Boot", RunSecureBootCheckAsync),
        new("fail2ban", RunFail2banCheckAsync),
    };

    // ------------------------------------------------------------------
    public Task RunSshRootLoginCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking SSH root login configuration...");
        const string path = "/etc/ssh/sshd_config";

        if (!File.Exists(path))
        {
            store.Add("SSH", "SSH Root Login", FindingStatus.Unknown, $"{path} not found - sshd may not be installed.");
            ConsoleUi.WriteStatus("i", "sshd_config not found (sshd not installed?)", ConsoleColor.DarkGray);
            return Task.CompletedTask;
        }

        var lines = File.ReadAllLines(path);
        var match = lines.FirstOrDefault(l => Regex.IsMatch(l.Trim(), @"^PermitRootLogin\s+\S+", RegexOptions.IgnoreCase));

        if (match is null)
        {
            store.Add("SSH", "SSH Root Login", FindingStatus.Info,
                "PermitRootLogin not explicitly set (falls back to the OpenSSH build default).");
            ConsoleUi.WriteStatus("i", "PermitRootLogin not explicitly set", ConsoleColor.DarkGray);
        }
        else if (match.Contains("yes", StringComparison.OrdinalIgnoreCase))
        {
            store.Add("SSH", "SSH Root Login", FindingStatus.Bad,
                "PermitRootLogin yes - root can authenticate over SSH directly.",
                "Set PermitRootLogin to 'no' or 'prohibit-password'.", Severity.High, internetExposed: true);
            ConsoleUi.WriteStatus("X", "PermitRootLogin yes", ConsoleColor.Red);
        }
        else
        {
            store.Add("SSH", "SSH Root Login", FindingStatus.Good, $"{match.Trim()}");
            ConsoleUi.WriteStatus("OK", "PermitRootLogin restricted", ConsoleColor.Green);
        }

        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    public async Task RunFirewallCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking firewall status...");

        if (PackageManager.ToolAvailable("ufw"))
        {
            var result = await PackageManager.RunAsync("ufw", "status");
            var inactive = result.Output.Contains("inactive", StringComparison.OrdinalIgnoreCase);
            if (inactive)
            {
                store.Add("Firewall", "ufw", FindingStatus.Bad, "ufw is installed but inactive.",
                    "Enable ufw ('ufw enable') or another firewall.", Severity.High, internetExposed: true);
                ConsoleUi.WriteStatus("X", "ufw is inactive", ConsoleColor.Red);
            }
            else
            {
                ConsoleUi.WriteStatus("OK", "ufw is active", ConsoleColor.Green);
            }
            return;
        }

        if (PackageManager.ToolAvailable("firewall-cmd"))
        {
            var result = await PackageManager.RunAsync("firewall-cmd", "--state");
            if (result.Output.Trim().Equals("running", StringComparison.OrdinalIgnoreCase))
            {
                ConsoleUi.WriteStatus("OK", "firewalld is running", ConsoleColor.Green);
            }
            else
            {
                store.Add("Firewall", "firewalld", FindingStatus.Bad, "firewalld is not running.",
                    "Start firewalld or configure another firewall.", Severity.High, internetExposed: true);
                ConsoleUi.WriteStatus("X", "firewalld is not running", ConsoleColor.Red);
            }
            return;
        }

        store.Add("Firewall", "Firewall Tool", FindingStatus.Unknown,
            "Neither ufw nor firewalld found - could not determine firewall state (raw iptables/nftables rules not parsed).",
            "Install/configure ufw or firewalld, or verify iptables/nftables rules manually.", Severity.Low);
        ConsoleUi.WriteStatus("!", "No recognized firewall front-end (ufw/firewalld) found", ConsoleColor.Yellow);
    }

    // ------------------------------------------------------------------
    public async Task RunDiskEncryptionCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking disk encryption (LUKS)...");
        if (!PackageManager.ToolAvailable("lsblk"))
        {
            store.Add("DiskEncryption", "LUKS", FindingStatus.Unknown, "lsblk not available.");
            return;
        }

        var result = await PackageManager.RunAsync("lsblk", "-J -o NAME,FSTYPE,MOUNTPOINT");
        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var devices = doc.RootElement.GetProperty("blockdevices");
            var anyLuks = false;
            foreach (var dev in devices.EnumerateArray())
            {
                var fstype = dev.TryGetProperty("fstype", out var ft) ? ft.GetString() : null;
                if (string.Equals(fstype, "crypto_LUKS", StringComparison.OrdinalIgnoreCase))
                {
                    anyLuks = true;
                }
            }

            if (anyLuks)
            {
                ConsoleUi.WriteStatus("OK", "At least one LUKS-encrypted block device found", ConsoleColor.Green);
            }
            else
            {
                store.Add("DiskEncryption", "LUKS", FindingStatus.Warning,
                    "No LUKS-encrypted block devices detected.",
                    "Consider full-disk encryption (LUKS) for data-at-rest protection.", Severity.Medium);
                ConsoleUi.WriteStatus("!", "No LUKS-encrypted devices found", ConsoleColor.Yellow);
            }
        }
        catch (JsonException)
        {
            store.Add("DiskEncryption", "LUKS", FindingStatus.Unknown, "Could not parse lsblk JSON output.");
        }
    }

    // ------------------------------------------------------------------
    public async Task RunSudoGroupCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking sudo/wheel group membership...");
        foreach (var groupName in new[] { "sudo", "wheel" })
        {
            var result = await PackageManager.RunAsync("getent", $"group {groupName}");
            if (!result.Success || string.IsNullOrWhiteSpace(result.Output)) continue;

            var fields = result.Output.Trim().Split(':');
            if (fields.Length < 4) continue;

            var members = fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            store.Add("Accounts", $"{groupName} Group Members", FindingStatus.Info, string.Join(", ", members));
            ConsoleUi.WriteStatus("i", $"'{groupName}' group has {members.Length} member(s)", ConsoleColor.Cyan);

            if (members.Length > _settings.MaxAdminAccounts)
            {
                store.Add("Accounts", "Excess Admins", FindingStatus.Warning,
                    $"{members.Length} accounts are in the '{groupName}' group (threshold: {_settings.MaxAdminAccounts}).",
                    "Apply least-privilege - remove unnecessary sudo group members.", Severity.Medium);
                ConsoleUi.WriteStatus("!", $"{members.Length} accounts have sudo rights (review recommended)", ConsoleColor.Yellow);
            }
            return;
        }

        ConsoleUi.WriteStatus("i", "Neither 'sudo' nor 'wheel' group found via getent", ConsoleColor.DarkGray);
    }

    // ------------------------------------------------------------------
    public async Task RunMacCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking mandatory access control (AppArmor/SELinux)...");

        if (PackageManager.ToolAvailable("aa-status"))
        {
            var result = await PackageManager.RunAsync("aa-status", "--enabled");
            ConsoleUi.WriteStatus(result.Success ? "OK" : "!",
                result.Success ? "AppArmor is enabled" : "AppArmor present but not enabled",
                result.Success ? ConsoleColor.Green : ConsoleColor.Yellow);
            if (!result.Success)
            {
                store.Add("MAC", "AppArmor", FindingStatus.Warning, "AppArmor is installed but not enabled.",
                    "Enable AppArmor enforcement.", Severity.Medium);
            }
            return;
        }

        if (PackageManager.ToolAvailable("getenforce"))
        {
            var result = await PackageManager.RunAsync("getenforce", "");
            var mode = result.Output.Trim();
            if (mode.Equals("Enforcing", StringComparison.OrdinalIgnoreCase))
            {
                ConsoleUi.WriteStatus("OK", "SELinux is Enforcing", ConsoleColor.Green);
            }
            else
            {
                store.Add("MAC", "SELinux", FindingStatus.Warning, $"SELinux mode is '{mode}' (not Enforcing).",
                    "Set SELinux to Enforcing mode.", Severity.Medium);
                ConsoleUi.WriteStatus("!", $"SELinux mode: {mode}", ConsoleColor.Yellow);
            }
            return;
        }

        store.Add("MAC", "AppArmor/SELinux", FindingStatus.Unknown, "Neither AppArmor nor SELinux tooling found.");
        ConsoleUi.WriteStatus("i", "No AppArmor/SELinux tooling detected", ConsoleColor.DarkGray);
    }

    // ------------------------------------------------------------------
    public Task RunUnattendedUpgradesCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking unattended-upgrades configuration...");
        const string path = "/etc/apt/apt.conf.d/20auto-upgrades";

        if (!File.Exists(path))
        {
            store.Add("Patching", "Unattended Upgrades", FindingStatus.Warning,
                $"{path} not found - automatic security updates likely not configured.",
                "Install and configure the unattended-upgrades package.", Severity.Medium);
            ConsoleUi.WriteStatus("!", "unattended-upgrades config not found", ConsoleColor.Yellow);
            return Task.CompletedTask;
        }

        var content = File.ReadAllText(path);
        var enabled = Regex.IsMatch(content, @"APT::Periodic::Unattended-Upgrade\s+""1""");
        if (enabled)
        {
            ConsoleUi.WriteStatus("OK", "Unattended upgrades enabled", ConsoleColor.Green);
        }
        else
        {
            store.Add("Patching", "Unattended Upgrades", FindingStatus.Warning,
                "unattended-upgrades config present but not enabled (value != 1).",
                "Set APT::Periodic::Unattended-Upgrade to \"1\".", Severity.Medium);
            ConsoleUi.WriteStatus("!", "Unattended upgrades not enabled", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    public async Task RunSecureBootCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Secure Boot state...");
        if (!PackageManager.ToolAvailable("mokutil"))
        {
            store.Add("ModernSecurity", "Secure Boot", FindingStatus.Unknown, "mokutil not installed - cannot query Secure Boot state.");
            ConsoleUi.WriteStatus("i", "mokutil not installed", ConsoleColor.DarkGray);
            return;
        }

        var result = await PackageManager.RunAsync("mokutil", "--sb-state");
        if (result.Output.Contains("SecureBoot enabled", StringComparison.OrdinalIgnoreCase))
        {
            ConsoleUi.WriteStatus("OK", "Secure Boot enabled", ConsoleColor.Green);
        }
        else
        {
            store.Add("ModernSecurity", "Secure Boot", FindingStatus.Bad, "Secure Boot is disabled or unsupported.",
                "Enable Secure Boot in firmware/UEFI settings.", Severity.High);
            ConsoleUi.WriteStatus("X", "Secure Boot is DISABLED", ConsoleColor.Red);
        }
    }

    // ------------------------------------------------------------------
    public async Task RunFail2banCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking fail2ban status...");
        if (!PackageManager.ToolAvailable("fail2ban-client"))
        {
            store.Add("Fail2ban", "fail2ban", FindingStatus.Info,
                "fail2ban not installed.", "Consider installing fail2ban for brute-force protection on exposed services.", Severity.Info);
            ConsoleUi.WriteStatus("i", "fail2ban not installed", ConsoleColor.DarkGray);
            return;
        }

        var result = await PackageManager.RunAsync("fail2ban-client", "status");
        ConsoleUi.WriteStatus(result.Success ? "OK" : "!",
            result.Success ? "fail2ban is running" : "fail2ban installed but not running",
            result.Success ? ConsoleColor.Green : ConsoleColor.Yellow);
        if (!result.Success)
        {
            store.Add("Fail2ban", "fail2ban", FindingStatus.Warning, "fail2ban is installed but not running.",
                "Start the fail2ban service.", Severity.Low);
        }
    }

    // ------------------------------------------------------------------
    // Software inventory - dpkg (Debian/Ubuntu family)
    // ------------------------------------------------------------------
    public async Task<List<SoftwareItem>> GetSoftwareInventoryAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Enumerating installed packages (dpkg)...");
        var software = new List<SoftwareItem>();

        if (!PackageManager.ToolAvailable("dpkg"))
        {
            ConsoleUi.WriteStatus("!", "dpkg not found - this build targets the Debian/Ubuntu family; " +
                "an RPM/pacman equivalent would need dnf/rpm or pacman parsing added separately.", ConsoleColor.Yellow);
            return software;
        }

        var result = await PackageManager.RunAsync("dpkg", "-l");
        foreach (var line in result.Output.Split('\n'))
        {
            if (!line.StartsWith("ii", StringComparison.Ordinal)) continue; // "ii" = installed, matches dpkg's own convention

            var fields = Regex.Split(line.Trim(), @"\s+");
            if (fields.Length >= 3)
            {
                software.Add(new SoftwareItem(fields[1], fields[2], null, "dpkg"));
            }
        }

        ConsoleUi.WriteStatus("i", $"{software.Count} package(s) found via dpkg", ConsoleColor.Cyan);
        store.Add("Software", "Installed Packages", FindingStatus.Info, $"{software.Count} packages enumerated via dpkg.");

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
