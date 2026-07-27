using System.Management;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Perseus.Reporting;

namespace Perseus.Audit;

[SupportedOSPlatform("windows")]
public sealed class WindowsCheckProvider : ICheckProvider
{
    private readonly AuditSettings _settings;
    private readonly AuditSignatures _signatures;

    public WindowsCheckProvider(AuditSettings settings, AuditSignatures signatures)
    {
        _settings = settings;
        _signatures = signatures;
    }

    public string PlatformLabel => "Windows";

    public IReadOnlyList<MenuCheck> Checks => new List<MenuCheck>
    {
        new("Missing Security Updates", RunWindowsUpdateCheckAsync),
        new("Local Administrator Accounts", RunLocalAdminCheckAsync),
        new("Windows Defender Health", RunDefenderCheckAsync),
        new("Firewall Audit", RunFirewallCheckAsync),
        new("RDP Configuration", RunRdpCheckAsync),
        new("SMB Configuration", RunSmbCheckAsync),
        new("UAC Configuration", RunUacCheckAsync),
        new("BitLocker Status", RunBitLockerCheckAsync),
        new("Modern Security (Secure Boot/VBS/Cred Guard/HVCI/LSA/WDigest/SmartScreen/ASR/LAPS)", RunModernSecurityCheckAsync),
        new("Persistence Check (Run keys, Startup, Scheduled Tasks, Unquoted Paths)", RunPersistenceCheckAsync),
    };

    // ------------------------------------------------------------------
    // Windows Update / patch status
    // ------------------------------------------------------------------
    public Task RunWindowsUpdateCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Windows Update / patch status...");
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Caption, BuildNumber FROM Win32_OperatingSystem");
            foreach (ManagementObject os in searcher.Get())
            {
                var caption = os["Caption"]?.ToString() ?? "Unknown";
                var build = os["BuildNumber"]?.ToString() ?? "Unknown";
                store.Add("Patching", "OS Version", FindingStatus.Info, $"{caption} (Build {build})");
                ConsoleUi.WriteStatus("i", $"OS: {caption} (Build {build})", ConsoleColor.Cyan);

                if (_signatures.UnsupportedOsPatterns.Any(p => caption.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    store.Add("Patching", "Unsupported OS", FindingStatus.Bad,
                        $"{caption} is end-of-life.", "Upgrade to a supported OS version.", Severity.Critical);
                    ConsoleUi.WriteStatus("X", "Operating system is unsupported / end-of-life", ConsoleColor.Red);
                }
            }

            DateTime? lastHotfix = null;
            string? lastHotfixId = null;
            using var hotfixSearcher = new ManagementObjectSearcher("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering");
            foreach (ManagementObject hf in hotfixSearcher.Get())
            {
                if (DateTime.TryParse(hf["InstalledOn"]?.ToString(), out var installedOn))
                {
                    if (lastHotfix is null || installedOn > lastHotfix) { lastHotfix = installedOn; lastHotfixId = hf["HotFixID"]?.ToString(); }
                }
            }

            if (lastHotfix is not null)
            {
                store.Add("Patching", "Last Update Installed", FindingStatus.Info, $"{lastHotfixId} on {lastHotfix}");
                ConsoleUi.WriteStatus("i", $"Last KB installed: {lastHotfixId} ({lastHotfix})", ConsoleColor.Cyan);

                var daysSince = (DateTime.Now - lastHotfix.Value).Days;
                if (daysSince > _settings.UpdateStalenessDays)
                {
                    store.Add("Patching", "Update Recency", FindingStatus.Warning,
                        $"No updates installed in {daysSince} days (threshold: {_settings.UpdateStalenessDays}).",
                        "Run Windows Update / check WSUS connectivity.", Severity.Medium);
                    ConsoleUi.WriteStatus("!", $"No updates in {daysSince} days", ConsoleColor.Yellow);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "Update cadence looks reasonable", ConsoleColor.Green);
                }
            }
            else
            {
                store.Add("Patching", "Update History", FindingStatus.Warning,
                    "Could not enumerate hotfix history.", "Verify Windows Update service is running.", Severity.Low);
            }

            // Pending updates via the Windows Update Agent COM API (late-bound - no
            // interop assembly needed, works the same way PowerShell's
            // New-Object -ComObject Microsoft.Update.Session did).
            try
            {
                var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
                if (sessionType is not null)
                {
                    dynamic session = Activator.CreateInstance(sessionType)!;
                    dynamic searcherObj = session.CreateUpdateSearcher();
                    dynamic result = searcherObj.Search("IsInstalled=0 and Type='Software'");
                    int pending = result.Updates.Count;
                    if (pending > 0)
                    {
                        store.Add("Patching", "Pending Updates", FindingStatus.Bad,
                            $"{pending} update(s) pending installation.", "Install pending Windows updates.", Severity.High);
                        ConsoleUi.WriteStatus("X", $"{pending} pending update(s) found", ConsoleColor.Red);
                    }
                    else
                    {
                        store.Add("Patching", "Pending Updates", FindingStatus.Good, "No pending updates detected.");
                        ConsoleUi.WriteStatus("OK", "No pending updates detected", ConsoleColor.Green);
                    }
                }
            }
            catch
            {
                ConsoleUi.WriteStatus("i", "Pending-update search unavailable (WUA COM API blocked/offline)", ConsoleColor.DarkGray);
            }
        }
        catch (Exception ex)
        {
            ConsoleUi.WriteStatus("!", $"Update check failed: {ex.Message}", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Local administrator accounts
    // ------------------------------------------------------------------
    public async Task RunLocalAdminCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking local administrator accounts...");
        var listResult = await PackageManager.RunAsync("net", "localgroup Administrators");
        if (!listResult.Success)
        {
            ConsoleUi.WriteStatus("!", "Local admin enumeration requires elevation", ConsoleColor.Yellow);
            return;
        }

        var names = ParseNetLocalGroupMembers(listResult.Output);
        store.Add("Accounts", "Administrator Group Members", FindingStatus.Info, string.Join(", ", names));
        ConsoleUi.WriteStatus("i", $"Local Administrators group has {names.Count} member(s)", ConsoleColor.Cyan);

        if (names.Count > _settings.MaxAdminAccounts)
        {
            store.Add("Accounts", "Excess Admins", FindingStatus.Warning,
                $"{names.Count} accounts have local admin rights (threshold: {_settings.MaxAdminAccounts}).",
                "Apply least-privilege - remove unnecessary admin members.", Severity.Medium);
            ConsoleUi.WriteStatus("!", $"{names.Count} accounts hold admin rights (review recommended)", ConsoleColor.Yellow);
        }

        foreach (var name in names)
        {
            var userResult = await PackageManager.RunAsync("net", $"user \"{name}\"");
            if (!userResult.Success) continue;

            if (userResult.Output.Contains("Password required", StringComparison.OrdinalIgnoreCase) &&
                userResult.Output.Contains("No", StringComparison.OrdinalIgnoreCase))
            {
                var line = userResult.Output.Split('\n').FirstOrDefault(l => l.Contains("Password required", StringComparison.OrdinalIgnoreCase));
                if (line is not null && line.Contains("No", StringComparison.OrdinalIgnoreCase))
                {
                    store.Add("Accounts", $"Blank/Optional Password: {name}", FindingStatus.Bad,
                        $"{name} does not require a password.", "Require strong passwords for all local accounts.", Severity.High);
                    ConsoleUi.WriteStatus("X", $"{name}: password not required", ConsoleColor.Red);
                }
            }
        }

        var adminEnabled = names.Any(n => n.Equals("Administrator", StringComparison.OrdinalIgnoreCase));
        if (adminEnabled)
        {
            store.Add("Accounts", "Built-in Administrator", FindingStatus.Warning,
                "Built-in Administrator account is present in the admin group (check if it's enabled).",
                "Disable the built-in Administrator account if not required.", Severity.Medium);
        }
    }

    private static List<string> ParseNetLocalGroupMembers(string output)
    {
        var lines = output.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var startIndex = lines.FindIndex(l => l.StartsWith("---"));
        if (startIndex < 0) return new List<string>();

        var names = new List<string>();
        for (var i = startIndex + 1; i < lines.Count; i++)
        {
            var trimmed = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase)) break;
            names.Add(trimmed);
        }
        return names;
    }

    // ------------------------------------------------------------------
    // Windows Defender
    // ------------------------------------------------------------------
    public Task RunDefenderCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Windows Defender health...");
        try
        {
            var scope = new ManagementScope(@"root\Microsoft\Windows\Defender");
            scope.Connect();
            var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus"));
            var results = searcher.Get();

            if (results.Count == 0)
            {
                store.Add("Defender", "Defender Status", FindingStatus.Warning,
                    "MSFT_MpComputerStatus returned no instances - Defender may be disabled or replaced.",
                    "Confirm an active, up-to-date endpoint protection product is installed.", Severity.Medium);
                ConsoleUi.WriteStatus("!", "Windows Defender WMI namespace unavailable (3rd-party AV or Defender disabled)", ConsoleColor.Yellow);
                return Task.CompletedTask;
            }

            foreach (ManagementObject mp in results)
            {
                var realTime = Convert.ToBoolean(mp["RealTimeProtectionEnabled"] ?? false);
                if (!realTime)
                {
                    store.Add("Defender", "Real-Time Protection", FindingStatus.Bad,
                        "Real-time protection is disabled.", "Enable real-time protection immediately.", Severity.Critical);
                    ConsoleUi.WriteStatus("X", "Real-time protection DISABLED", ConsoleColor.Red);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "Real-time protection enabled", ConsoleColor.Green);
                }

                var tamperProtected = Convert.ToBoolean(mp["IsTamperProtected"] ?? false);
                if (!tamperProtected)
                {
                    store.Add("Defender", "Tamper Protection", FindingStatus.Warning,
                        "Tamper Protection is off.", "Enable Tamper Protection in Windows Security.", Severity.Medium);
                    ConsoleUi.WriteStatus("!", "Tamper Protection disabled", ConsoleColor.Yellow);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "Tamper Protection enabled", ConsoleColor.Green);
                }

                if (DateTime.TryParse(mp["AntivirusSignatureLastUpdated"]?.ToString(), out var sigDate))
                {
                    var ageDays = (DateTime.Now - sigDate).Days;
                    if (ageDays > 7)
                    {
                        store.Add("Defender", "Signature Age", FindingStatus.Bad,
                            $"Signatures are {ageDays} days old.", "Update Defender signatures.", Severity.High);
                        ConsoleUi.WriteStatus("X", $"Signatures are {ageDays} days old", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleUi.WriteStatus("OK", $"Signatures up to date ({ageDays}d old)", ConsoleColor.Green);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            store.Add("Defender", "Defender Status", FindingStatus.Warning,
                $"MSFT_MpComputerStatus query failed: {ex.Message}",
                "Confirm an active, up-to-date endpoint protection product is installed.", Severity.Medium);
            ConsoleUi.WriteStatus("!", "Windows Defender WMI namespace unavailable (3rd-party AV or Defender disabled)", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Firewall (via netsh - documented, stable CLI surface)
    // ------------------------------------------------------------------
    public async Task RunFirewallCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Windows Firewall...");
        var result = await PackageManager.RunAsync("netsh", "advfirewall show allprofiles state");
        if (!result.Success)
        {
            ConsoleUi.WriteStatus("!", "Could not query firewall profiles", ConsoleColor.Yellow);
            return;
        }

        string? currentProfile = null;
        foreach (var rawLine in result.Output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.EndsWith("Profile Settings:", StringComparison.OrdinalIgnoreCase))
            {
                currentProfile = line.Replace("Profile Settings:", "").Trim();
            }
            else if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase) && currentProfile is not null)
            {
                var isOff = line.Contains("OFF", StringComparison.OrdinalIgnoreCase);
                if (isOff)
                {
                    store.Add("Firewall", $"{currentProfile} Profile", FindingStatus.Bad,
                        $"{currentProfile} firewall profile is disabled.", "Enable the firewall for all profiles.",
                        Severity.High, internetExposed: true);
                    ConsoleUi.WriteStatus("X", $"{currentProfile} profile: DISABLED", ConsoleColor.Red);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", $"{currentProfile} profile: enabled", ConsoleColor.Green);
                }
                currentProfile = null;
            }
        }
    }

    // ------------------------------------------------------------------
    // RDP (registry - same keys as the PowerShell version)
    // ------------------------------------------------------------------
    public Task RunRdpCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking Remote Desktop configuration...");
        try
        {
            using var tsKey = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\Terminal Server");
            var deny = tsKey?.GetValue("fDenyTSConnections");

            if (deny is int denyVal && denyVal == 0)
            {
                store.Add("RDP", "RDP Enabled", FindingStatus.Warning,
                    "Remote Desktop is enabled.", "Disable RDP if not needed, or restrict via firewall/VPN.",
                    Severity.Medium, internetExposed: true);
                ConsoleUi.WriteStatus("!", "RDP is ENABLED", ConsoleColor.Yellow);

                using var rdpTcpKey = Registry.LocalMachine.OpenSubKey(
                    @"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
                var nla = rdpTcpKey?.GetValue("UserAuthentication");
                if (nla is int nlaVal && nlaVal == 0)
                {
                    store.Add("RDP", "Network Level Authentication", FindingStatus.Bad,
                        "NLA is disabled for RDP.", "Enable Network Level Authentication.",
                        Severity.High, internetExposed: true);
                    ConsoleUi.WriteStatus("X", "Network Level Authentication (NLA) DISABLED", ConsoleColor.Red);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "NLA enabled", ConsoleColor.Green);
                }

                var enc = rdpTcpKey?.GetValue("MinEncryptionLevel");
                if (enc is int encVal && encVal < 3)
                {
                    store.Add("RDP", "RDP Encryption Level", FindingStatus.Warning,
                        $"MinEncryptionLevel = {encVal} (below High).", "Set RDP encryption level to High (3).", Severity.Medium);
                }
            }
            else
            {
                ConsoleUi.WriteStatus("OK", "RDP is disabled", ConsoleColor.Green);
                store.Add("RDP", "RDP Enabled", FindingStatus.Good, "RDP disabled.");
            }
        }
        catch (Exception ex)
        {
            ConsoleUi.WriteStatus("!", $"Could not read RDP registry keys: {ex.Message}", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // SMB (registry keys - documented SMB1/signing values)
    // ------------------------------------------------------------------
    public Task RunSmbCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking SMB configuration...");
        try
        {
            using var lanmanKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            var smb1 = lanmanKey?.GetValue("SMB1");
            if (smb1 is int smb1Val && smb1Val == 1)
            {
                store.Add("SMB", "SMBv1", FindingStatus.Bad,
                    "SMBv1 protocol is enabled.", "Disable SMBv1 (vulnerable to EternalBlue-class exploits).",
                    Severity.Critical, internetExposed: true);
                ConsoleUi.WriteStatus("X", "SMBv1 is ENABLED (legacy, high risk)", ConsoleColor.Red);
            }
            else
            {
                ConsoleUi.WriteStatus("OK", "SMBv1 disabled/not installed", ConsoleColor.Green);
            }

            var signing = lanmanKey?.GetValue("RequireSecuritySignature");
            if (signing is int signingVal && signingVal == 0)
            {
                store.Add("SMB", "SMB Signing", FindingStatus.Warning,
                    "SMB signing is not required.", "Require SMB signing to prevent relay attacks.", Severity.Medium);
                ConsoleUi.WriteStatus("!", "SMB signing not required", ConsoleColor.Yellow);
            }
            else
            {
                ConsoleUi.WriteStatus("OK", "SMB signing required", ConsoleColor.Green);
            }
        }
        catch (Exception ex)
        {
            ConsoleUi.WriteStatus("!", $"SMB check incomplete: {ex.Message}", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // UAC
    // ------------------------------------------------------------------
    public Task RunUacCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking User Account Control (UAC)...");
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            var enableLua = key?.GetValue("EnableLUA");
            if (enableLua is int luaVal && luaVal == 0)
            {
                store.Add("UAC", "UAC Enabled", FindingStatus.Bad, "UAC is disabled.", "Enable UAC (EnableLUA=1).", Severity.High);
                ConsoleUi.WriteStatus("X", "UAC is DISABLED", ConsoleColor.Red);
            }
            else
            {
                ConsoleUi.WriteStatus("OK", "UAC enabled", ConsoleColor.Green);
            }

            var consentPrompt = key?.GetValue("ConsentPromptBehaviorAdmin");
            if (consentPrompt is int consentVal && consentVal == 0)
            {
                store.Add("UAC", "Admin Approval Mode", FindingStatus.Bad,
                    "Admins elevate silently without prompting.",
                    "Set admin approval mode to prompt for consent/credentials.", Severity.High);
                ConsoleUi.WriteStatus("X", "Admin actions elevate WITHOUT prompting", ConsoleColor.Red);
            }
        }
        catch (Exception ex)
        {
            ConsoleUi.WriteStatus("!", $"Could not read UAC registry keys: {ex.Message}", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // BitLocker (WMI: root\cimv2\Security\MicrosoftVolumeEncryption)
    // ------------------------------------------------------------------
    public Task RunBitLockerCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking BitLocker status...");
        try
        {
            var scope = new ManagementScope(@"root\cimv2\Security\MicrosoftVolumeEncryption");
            scope.Connect();
            var searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'"));

            var found = false;
            foreach (ManagementObject vol in searcher.Get())
            {
                found = true;
                var protectionStatus = Convert.ToInt32(vol["ProtectionStatus"] ?? 0);
                if (protectionStatus != 1)
                {
                    store.Add("BitLocker", "Drive C:", FindingStatus.Bad,
                        "C: is not encrypted.", "Enable BitLocker on the OS drive.", Severity.High);
                    ConsoleUi.WriteStatus("X", "C: NOT encrypted", ConsoleColor.Red);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "C: encrypted", ConsoleColor.Green);
                }
            }

            if (!found)
            {
                ConsoleUi.WriteStatus("!", "BitLocker WMI class unavailable (not supported on this edition/VM)", ConsoleColor.Yellow);
            }
        }
        catch (Exception ex)
        {
            ConsoleUi.WriteStatus("!", $"BitLocker check unavailable: {ex.Message}", ConsoleColor.Yellow);
        }
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Modern security posture
    // ------------------------------------------------------------------
    public Task RunModernSecurityCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking modern Windows security posture...");

        // Secure Boot - documented registry key (avoids native GetFirmwareEnvironmentVariable P/Invoke)
        try
        {
            using var sbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            var sbEnabled = sbKey?.GetValue("UEFISecureBootEnabled");
            if (sbEnabled is int sbVal)
            {
                if (sbVal == 0)
                {
                    store.Add("ModernSecurity", "Secure Boot", FindingStatus.Bad,
                        "Secure Boot is disabled.", "Enable Secure Boot in firmware/UEFI settings.", Severity.High);
                    ConsoleUi.WriteStatus("X", "Secure Boot is DISABLED", ConsoleColor.Red);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "Secure Boot enabled", ConsoleColor.Green);
                }
            }
            else
            {
                store.Add("ModernSecurity", "Secure Boot", FindingStatus.Unknown,
                    "Could not determine Secure Boot state (legacy BIOS or key absent).",
                    "Verify manually in firmware settings.", Severity.Low);
            }
        }
        catch
        {
            ConsoleUi.WriteStatus("i", "Secure Boot state unknown (legacy BIOS, or requires elevation)", ConsoleColor.DarkGray);
        }

        // VBS / Credential Guard / HVCI via Device Guard WMI class
        try
        {
            var scope = new ManagementScope(@"root\Microsoft\Windows\DeviceGuard");
            scope.Connect();
            var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_DeviceGuard"));
            foreach (ManagementObject dg in searcher.Get())
            {
                var vbsStatus = Convert.ToInt32(dg["VirtualizationBasedSecurityStatus"] ?? 0);
                var configured = ((ushort[]?)dg["SecurityServicesConfigured"]) ?? Array.Empty<ushort>();
                var running = ((ushort[]?)dg["SecurityServicesRunning"]) ?? Array.Empty<ushort>();

                if (vbsStatus != 2)
                {
                    store.Add("ModernSecurity", "Virtualization-Based Security", FindingStatus.Warning,
                        "VBS is not running.", "Enable VBS (Core Isolation) if hardware supports it.", Severity.Medium);
                    ConsoleUi.WriteStatus("!", "VBS not running", ConsoleColor.Yellow);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "VBS running", ConsoleColor.Green);
                }

                var cgConfigured = configured.Contains((ushort)1);
                var cgRunning = running.Contains((ushort)1);
                var hvciRunning = running.Contains((ushort)2);

                if (cgConfigured && !cgRunning)
                {
                    store.Add("ModernSecurity", "Credential Guard", FindingStatus.Bad,
                        "Credential Guard is configured but not running.",
                        "Investigate why Credential Guard failed to start (hardware/driver compatibility).", Severity.High);
                    ConsoleUi.WriteStatus("X", "Credential Guard configured but NOT running", ConsoleColor.Red);
                }
                else if (cgRunning)
                {
                    ConsoleUi.WriteStatus("OK", "Credential Guard running", ConsoleColor.Green);
                }

                if (!hvciRunning)
                {
                    store.Add("ModernSecurity", "Memory Integrity (HVCI)", FindingStatus.Warning,
                        "HVCI/Memory Integrity is not running.",
                        "Enable Memory Integrity under Windows Security > Device Security.", Severity.Medium);
                    ConsoleUi.WriteStatus("!", "HVCI (Memory Integrity) not running", ConsoleColor.Yellow);
                }
                else
                {
                    ConsoleUi.WriteStatus("OK", "HVCI (Memory Integrity) running", ConsoleColor.Green);
                }
            }
        }
        catch
        {
            store.Add("ModernSecurity", "VBS / Credential Guard / HVCI", FindingStatus.Unknown,
                "Device Guard WMI class unavailable.", "Check manually via System Information (msinfo32).", Severity.Low);
            ConsoleUi.WriteStatus("i", "VBS/Credential Guard/HVCI status unavailable on this SKU/VM", ConsoleColor.DarkGray);
        }

        // LSA Protection (RunAsPPL)
        try
        {
            using var lsaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            var ppl = lsaKey?.GetValue("RunAsPPL");
            if (ppl is int pplVal && pplVal == 1)
            {
                ConsoleUi.WriteStatus("OK", "LSA Protection enabled", ConsoleColor.Green);
            }
            else
            {
                store.Add("ModernSecurity", "LSA Protection", FindingStatus.Warning,
                    "LSA Protection (RunAsPPL) is not enabled.",
                    "Enable LSA Protection to harden LSASS against credential dumping.", Severity.Medium);
                ConsoleUi.WriteStatus("!", "LSA Protection (RunAsPPL) disabled", ConsoleColor.Yellow);
            }
        }
        catch
        {
            ConsoleUi.WriteStatus("i", "LSA Protection value not set (treated as disabled by default)", ConsoleColor.DarkGray);
        }

        // WDigest
        try
        {
            using var wdKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest");
            var wdigest = wdKey?.GetValue("UseLogonCredential");
            if (wdigest is int wdVal && wdVal == 1)
            {
                store.Add("ModernSecurity", "WDigest", FindingStatus.Bad,
                    "WDigest is configured to cache plaintext credentials in memory.",
                    "Set UseLogonCredential to 0.", Severity.High);
                ConsoleUi.WriteStatus("X", "WDigest plaintext credential caching ENABLED", ConsoleColor.Red);
            }
            else
            {
                ConsoleUi.WriteStatus("OK", "WDigest plaintext credential caching disabled/default", ConsoleColor.Green);
            }
        }
        catch { /* key absence = disabled by default, nothing to report */ }

        // SmartScreen
        try
        {
            using var ssKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System");
            var ssVal = ssKey?.GetValue("EnableSmartScreen");
            if (ssVal is int ss && ss == 0)
            {
                store.Add("ModernSecurity", "SmartScreen", FindingStatus.Warning,
                    "SmartScreen is disabled by policy.", "Re-enable SmartScreen for app/browser protection.", Severity.Medium);
                ConsoleUi.WriteStatus("!", "SmartScreen disabled by policy", ConsoleColor.Yellow);
            }
        }
        catch { /* not configured - fine, uses OS default */ }

        // LAPS presence
        var lapsPresent = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft Services\AdmPwd") is not null;
        if (!lapsPresent)
        {
            store.Add("ModernSecurity", "LAPS", FindingStatus.Info,
                "No LAPS (Local Administrator Password Solution) policy detected.",
                "On domain-joined fleets, deploy LAPS to rotate local admin passwords.", Severity.Info);
            ConsoleUi.WriteStatus("i", "LAPS not detected (relevant mainly for domain-joined fleets)", ConsoleColor.DarkGray);
        }
        else
        {
            ConsoleUi.WriteStatus("OK", "LAPS policy detected", ConsoleColor.Green);
        }

        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Persistence - Run/RunOnce keys, Startup folder, scheduled tasks, unquoted service paths
    // ------------------------------------------------------------------
    public async Task RunPersistenceCheckAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Checking common persistence locations...");

        var runKeyPatterns = new[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        };

        var runKeyRegex = new System.Text.RegularExpressions.Regex(_signatures.RunKeySuspiciousPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var tempPathRegex = new System.Text.RegularExpressions.Regex(_signatures.TempPathPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        var runEntryCount = 0;
        foreach (var (hive, path) in runKeyPatterns)
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) continue;
            foreach (var valueName in key.GetValueNames())
            {
                runEntryCount++;
                var value = key.GetValue(valueName)?.ToString() ?? "";
                if (runKeyRegex.IsMatch(value))
                {
                    store.Add("Persistence", $"Run Key: {valueName}", FindingStatus.Bad,
                        $@"{path}\{valueName} = {value}",
                        "Investigate this autorun entry - looks like an encoded/hidden PowerShell invocation.", Severity.Critical);
                    ConsoleUi.WriteStatus("X", $"Suspicious autorun: {valueName}", ConsoleColor.Red);
                }
                else if (tempPathRegex.IsMatch(value))
                {
                    store.Add("Persistence", $"Run Key: {valueName}", FindingStatus.Warning,
                        $"{path}\\{valueName} launches from a temp directory: {value}",
                        "Verify legitimacy - execution from temp folders is a common persistence pattern.", Severity.Medium);
                    ConsoleUi.WriteStatus("!", $"Autorun from temp path: {valueName}", ConsoleColor.Yellow);
                }
            }
        }
        store.Add("Persistence", "Run/RunOnce Entries", FindingStatus.Info, $"{runEntryCount} autorun entr(y/ies) across Run/RunOnce keys.");
        ConsoleUi.WriteStatus("i", $"{runEntryCount} total Run/RunOnce entries reviewed", ConsoleColor.Cyan);

        // Startup folders
        foreach (var folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        })
        {
            if (!Directory.Exists(folder)) continue;
            var files = Directory.GetFiles(folder);
            foreach (var file in files)
            {
                store.Add("Persistence", $"Startup Item: {Path.GetFileName(file)}", FindingStatus.Info, $"Found in {folder}");
            }
            if (files.Length > 0) ConsoleUi.WriteStatus("i", $"{files.Length} item(s) in {folder}", ConsoleColor.Cyan);
        }

        // Scheduled tasks via schtasks (documented CLI, avoids Task Scheduler COM interop)
        var taskRegex = new System.Text.RegularExpressions.Regex(_signatures.ScheduledTaskSuspiciousPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var tasksResult = await PackageManager.RunAsync("schtasks", "/query /fo LIST /v");
        if (tasksResult.Success)
        {
            var blocks = tasksResult.Output.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);
            var suspiciousCount = 0;
            foreach (var block in blocks)
            {
                var taskNameLine = block.Split('\n').FirstOrDefault(l => l.StartsWith("TaskName:", StringComparison.OrdinalIgnoreCase));
                var actionLine = block.Split('\n').FirstOrDefault(l => l.StartsWith("Task To Run:", StringComparison.OrdinalIgnoreCase));
                if (actionLine is null) continue;

                if (actionLine.Contains("powershell", StringComparison.OrdinalIgnoreCase) && taskRegex.IsMatch(actionLine))
                {
                    suspiciousCount++;
                    var taskName = taskNameLine?.Replace("TaskName:", "").Trim() ?? "unknown";
                    store.Add("Persistence", $"Scheduled Task: {taskName}", FindingStatus.Bad,
                        $"Task '{taskName}' runs: {actionLine.Trim()}",
                        "Review this scheduled task - encoded/download-and-execute PowerShell patterns are common malware persistence.",
                        Severity.Critical);
                    ConsoleUi.WriteStatus("X", $"Suspicious scheduled task: {taskName}", ConsoleColor.Red);
                }
            }
            ConsoleUi.WriteStatus("i", $"{blocks.Length} scheduled task(s) reviewed ({suspiciousCount} flagged)", ConsoleColor.Cyan);
        }
        else
        {
            ConsoleUi.WriteStatus("!", "Could not enumerate scheduled tasks", ConsoleColor.Yellow);
        }

        // Unquoted service paths via WMI Win32_Service
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, PathName FROM Win32_Service");
            foreach (ManagementObject svc in searcher.Get())
            {
                var pathName = svc["PathName"]?.ToString();
                var name = svc["Name"]?.ToString() ?? "unknown";
                if (string.IsNullOrEmpty(pathName) || pathName.StartsWith('"')) continue;
                if (!pathName.Contains(".exe", StringComparison.OrdinalIgnoreCase)) continue;

                var exeIndex = pathName.ToLowerInvariant().IndexOf(".exe", StringComparison.Ordinal);
                var beforeExe = pathName[..exeIndex];
                if (beforeExe.Contains(' '))
                {
                    store.Add("Persistence", $"Unquoted Service Path: {name}", FindingStatus.Warning,
                        $"{name}: {pathName}",
                        "Quote the service binary path to prevent path-interception privilege escalation.", Severity.Medium);
                    ConsoleUi.WriteStatus("!", $"Unquoted path: {name}", ConsoleColor.Yellow);
                }
            }
        }
        catch (Exception ex)
        {
            ConsoleUi.WriteStatus("!", $"Could not enumerate services for unquoted-path check: {ex.Message}", ConsoleColor.Yellow);
        }
    }

    // ------------------------------------------------------------------
    // Software inventory: registry uninstall keys + winget + (optional) AppX via PowerShell
    // ------------------------------------------------------------------
    public async Task<List<SoftwareItem>> GetSoftwareInventoryAsync(FindingStore store)
    {
        Console.WriteLine("\n[*] Enumerating installed software...");
        var software = new List<SoftwareItem>();

        foreach (var (hive, path) in new[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        })
        {
            using var uninstallKey = hive.OpenSubKey(path);
            if (uninstallKey is null) continue;
            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                using var subKey = uninstallKey.OpenSubKey(subKeyName);
                var name = subKey?.GetValue("DisplayName")?.ToString();
                var version = subKey?.GetValue("DisplayVersion")?.ToString();
                if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(version)) continue;
                software.Add(new SoftwareItem(name, version, subKey?.GetValue("Publisher")?.ToString(), "Registry"));
            }
        }

        // winget-managed packages
        if (PackageManager.ToolAvailable("winget"))
        {
            var wingetResult = await PackageManager.RunAsync("winget", "list --accept-source-agreements");
            var lines = wingetResult.Output.Split('\n');
            var headerIndex = Array.FindIndex(lines, l => l.TrimStart().StartsWith("Name", StringComparison.Ordinal) && l.Contains("Id"));
            if (headerIndex >= 0)
            {
                for (var i = headerIndex + 1; i < lines.Length; i++)
                {
                    var cols = System.Text.RegularExpressions.Regex.Split(lines[i].Trim(), @"\s{2,}");
                    if (cols.Length >= 3 && !string.IsNullOrWhiteSpace(cols[0]))
                    {
                        software.Add(new SoftwareItem(cols[0], cols[2], null, "winget"));
                    }
                }
            }
        }

        software = software.DistinctBy(s => s.Name).OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();

        ConsoleUi.WriteStatus("i", $"{software.Count} application(s) found", ConsoleColor.Cyan);
        store.Add("Software", "Installed Applications", FindingStatus.Info, $"{software.Count} applications enumerated.");

        foreach (var item in software)
        {
            if (_signatures.SoftwareWatchlist.Any(w => item.Name.Contains(w, StringComparison.OrdinalIgnoreCase)))
            {
                store.Add("Software", item.Name, FindingStatus.Warning,
                    $"Version {item.Version} - historically frequent CVE target.",
                    "Verify this is the latest version and patch/remove if unused.", Severity.Low);
                ConsoleUi.WriteStatus("!", $"{item.Name} {item.Version} - check for updates", ConsoleColor.Yellow);
            }
        }

        return software;
    }
}
