using System.Text.Json;
using System.Text.Json.Serialization;
using Perseus.Reporting;

namespace Perseus.Audit;

public sealed class AuditSettings
{
    public Dictionary<string, string> RiskyPorts { get; set; } = new()
    {
        ["21"] = "FTP", ["22"] = "SSH", ["23"] = "Telnet", ["135"] = "RPC", ["139"] = "NetBIOS",
        ["445"] = "SMB", ["3389"] = "RDP", ["5985"] = "WinRM HTTP", ["5986"] = "WinRM HTTPS"
    };
    public int MaxCveTargets { get; set; } = 12;
    public string NvdApiKey { get; set; } = "";
    public int NvdDelayMs { get; set; } = 700;
    public int UpdateStalenessDays { get; set; } = 60;
    public int MaxAdminAccounts { get; set; } = 3;
}

public sealed class AuditSignatures
{
    public List<string> UnsupportedOsPatterns { get; set; } = new() { "Windows 7", "Windows 8", "Windows Vista", "Windows XP", "Windows Server 2008" };
    public List<string> SoftwareWatchlist { get; set; } = new() { "Java", "Adobe Acrobat", "Adobe Reader", "WinRAR", "7-Zip", "VNC", "TeamViewer", "Flash" };
    public string CveWatchlistPattern { get; set; } = @"Chrome|Firefox|Edge|Java|Adobe|OpenSSL|VLC|7-Zip|WinRAR|Zoom|Putty|Notepad\+\+";
    public string RunKeySuspiciousPattern { get; set; } = @"powershell(\.exe)?.*(-enc|-e |EncodedCommand|-w hidden|-windowstyle hidden)";
    public string TempPathPattern { get; set; } = @"\\(Temp|AppData\\Local\\Temp)\\";
    public string ScheduledTaskSuspiciousPattern { get; set; } = @"-enc|EncodedCommand|-nop.*-w hidden|IEX|Invoke-Expression|DownloadString";
}

public static class ConfigLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public static AuditSettings LoadSettings(string configDir)
    {
        var path = Path.Combine(configDir, "settings.json");
        return LoadOrCreate(path, new AuditSettings());
    }

    public static AuditSignatures LoadSignatures(string configDir)
    {
        var path = Path.Combine(configDir, "signatures.json");
        return LoadOrCreate(path, new AuditSignatures());
    }

    public static void SaveSettings(string configDir, AuditSettings settings)
    {
        Directory.CreateDirectory(configDir);
        var path = Path.Combine(configDir, "settings.json");
        File.WriteAllText(path, JsonSerializer.Serialize(settings, Options));
    }

    private static T LoadOrCreate<T>(string path, T defaultValue) where T : class
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        if (File.Exists(path))
        {
            try
            {
                var json = File.ReadAllText(path);
                var loaded = JsonSerializer.Deserialize<T>(json, Options);
                if (loaded is not null)
                {
                    ConsoleUi.WriteStatus("i", $"Loaded {Path.GetFileName(path)}", ConsoleColor.DarkGray);
                    return loaded;
                }
            }
            catch
            {
                ConsoleUi.WriteStatus("!", $"{Path.GetFileName(path)} found but could not be parsed - using defaults", ConsoleColor.Yellow);
            }
        }
        else
        {
            try { File.WriteAllText(path, JsonSerializer.Serialize(defaultValue, Options)); } catch { /* best effort */ }
        }

        return defaultValue;
    }
}
