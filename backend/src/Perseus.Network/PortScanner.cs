using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Perseus.Audit;
using Perseus.Reporting;

namespace Perseus.Network;

public sealed record ListeningPort(int Port, int? Pid, string ProcessName, string? Path, string? ServiceName);

public static class PortScanner
{
    public static async Task<List<ListeningPort>> GetListeningPortsAsync()
    {
        return PlatformHelper.Current switch
        {
            Platform.Windows => await GetWindowsPortsAsync(),
            Platform.Linux => GetLinuxPorts(),
            Platform.MacOs => await GetMacPortsAsync(),
            _ => new List<ListeningPort>()
        };
    }

    public static async Task RunCheckAsync(FindingStore store, Dictionary<string, string> riskyPorts, List<ListeningPort>? knownPorts = null)
    {
        Console.WriteLine("\n[*] Checking listening network ports...");
        var ports = knownPorts ?? await GetListeningPortsAsync();

        var risky = ports.Where(p => riskyPorts.ContainsKey(p.Port.ToString(CultureInfo.InvariantCulture))).ToList();
        foreach (var p in risky)
        {
            var label = riskyPorts[p.Port.ToString(CultureInfo.InvariantCulture)];
            var owner = p.ServiceName is not null ? $"service '{p.ServiceName}'"
                : p.Path is not null ? p.Path
                : $"{p.ProcessName} (PID {p.Pid?.ToString() ?? "?"})";

            store.Add("Network", $"Port {p.Port} ({label})", FindingStatus.Warning,
                $"{label} listening on port {p.Port}, owned by {owner}.",
                $"Restrict {label} exposure to trusted networks/VPN only; verify {owner} is expected.",
                Severity.Medium, internetExposed: true);
            ConsoleUi.WriteStatus("!", $"Port {p.Port} open ({label}) - {owner}", ConsoleColor.Yellow);
        }

        store.Add("Network", "Total Listening Ports", FindingStatus.Info, $"{ports.Count} TCP port(s) listening.");
        ConsoleUi.WriteStatus("i", $"{ports.Count} total listening TCP port(s)", ConsoleColor.Cyan);
    }

    // ------------------------------------------------------------------
    // Windows: netstat for port/PID, tasklist for svchost service names
    // ------------------------------------------------------------------
    private static async Task<List<ListeningPort>> GetWindowsPortsAsync()
    {
        var result = new List<ListeningPort>();
        var netstat = await PackageManager.RunAsync("netstat", "-ano -p TCP");
        if (!netstat.Success) return result;

        foreach (var line in netstat.Output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;
            if (!trimmed.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;

            var cols = Regex.Split(trimmed, @"\s+");
            // TCP  0.0.0.0:445  0.0.0.0:0  LISTENING  4
            if (cols.Length < 5) continue;

            var localAddr = cols[1];
            var portIndex = localAddr.LastIndexOf(':');
            if (portIndex < 0 || !int.TryParse(localAddr[(portIndex + 1)..], out var port)) continue;
            if (!int.TryParse(cols[4], out var pid)) continue;

            string? processName = null, servicePath = null, serviceName = null;
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                processName = proc.ProcessName;
                try { servicePath = proc.MainModule?.FileName; } catch { /* access denied for some system processes */ }
            }
            catch { processName = "Unknown"; }

            if (string.Equals(processName, "svchost", StringComparison.OrdinalIgnoreCase))
            {
                var tasklist = await PackageManager.RunAsync("tasklist", $"/svc /fi \"PID eq {pid}\"");
                var svcLine = tasklist.Output.Split('\n').FirstOrDefault(l => l.Contains(pid.ToString(CultureInfo.InvariantCulture)));
                if (svcLine is not null)
                {
                    var svcCols = Regex.Split(svcLine.Trim(), @"\s{2,}");
                    if (svcCols.Length >= 3) serviceName = svcCols[2];
                }
            }

            result.Add(new ListeningPort(port, pid, processName ?? "Unknown", servicePath, serviceName));
        }

        return result.DistinctBy(p => p.Port).ToList();
    }

    // ------------------------------------------------------------------
    // Linux: /proc/net/tcp (+tcp6) -> inode -> /proc/*/fd/* -> pid -> /proc/<pid>/comm+exe
    // Format verified against a real /proc/net/tcp in this sandbox before writing this.
    // ------------------------------------------------------------------
    private static List<ListeningPort> GetLinuxPorts()
    {
        var result = new List<ListeningPort>();
        var inodeToPort = new Dictionary<string, int>();

        foreach (var procFile in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
        {
            if (!File.Exists(procFile)) continue;
            var lines = File.ReadAllLines(procFile).Skip(1);
            foreach (var line in lines)
            {
                var cols = Regex.Split(line.Trim(), @"\s+");
                if (cols.Length < 10) continue;

                var state = cols[3];
                if (!state.Equals("0A", StringComparison.OrdinalIgnoreCase)) continue; // 0A = TCP_LISTEN

                var localAddress = cols[1];
                var portHex = localAddress.Split(':').ElementAtOrDefault(1);
                if (portHex is null || !int.TryParse(portHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var port)) continue;

                var inode = cols[9];
                if (inode != "0") inodeToPort[inode] = port;
            }
        }

        if (inodeToPort.Count == 0) return result;

        var portToProcess = new Dictionary<int, (int Pid, string Name, string? Path)>();
        string[] pidDirs;
        try { pidDirs = Directory.GetDirectories("/proc").Where(d => int.TryParse(Path.GetFileName(d), out _)).ToArray(); }
        catch { return result; }

        foreach (var pidDir in pidDirs)
        {
            if (!int.TryParse(Path.GetFileName(pidDir), out var pid)) continue;
            var fdDir = Path.Combine(pidDir, "fd");
            string[] fds;
            try { fds = Directory.GetFileSystemEntries(fdDir); } catch { continue; } // permission denied for other users' processes

            foreach (var fd in fds)
            {
                string target;
                try { target = new FileInfo(fd).LinkTarget ?? ""; } catch { continue; }

                var match = Regex.Match(target, @"socket:\[(\d+)\]");
                if (!match.Success) continue;
                var inode = match.Groups[1].Value;
                if (!inodeToPort.TryGetValue(inode, out var port)) continue;
                if (portToProcess.ContainsKey(port)) continue;

                var name = TryRead(Path.Combine(pidDir, "comm"))?.Trim() ?? "unknown";
                string? exePath = null;
                try { exePath = new FileInfo(Path.Combine(pidDir, "exe")).LinkTarget; } catch { /* needs matching uid or root */ }
                portToProcess[port] = (pid, name, exePath);
            }
        }

        foreach (var (inode, port) in inodeToPort)
        {
            if (portToProcess.TryGetValue(port, out var proc))
            {
                result.Add(new ListeningPort(port, proc.Pid, proc.Name, proc.Path, null));
            }
            else
            {
                // Could not attribute - typically means the owning process belongs to
                // another user and /proc/<pid>/fd isn't readable without root.
                result.Add(new ListeningPort(port, null, "Unknown", null, null));
            }
        }

        return result.DistinctBy(p => p.Port).ToList();
    }

    private static string? TryRead(string path)
    {
        try { return File.ReadAllText(path); } catch { return null; }
    }

    // ------------------------------------------------------------------
    // macOS: lsof (standard, pre-installed tool)
    // ------------------------------------------------------------------
    private static async Task<List<ListeningPort>> GetMacPortsAsync()
    {
        var result = new List<ListeningPort>();
        var lsof = await PackageManager.RunAsync("lsof", "-iTCP -sTCP:LISTEN -P -n");
        if (!lsof.Success) return result;

        foreach (var line in lsof.Output.Split('\n').Skip(1)) // skip header row
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var cols = Regex.Split(line.Trim(), @"\s+");
            // COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
            if (cols.Length < 9) continue;

            var name = cols[0];
            if (!int.TryParse(cols[1], out var pid)) continue;
            var addressField = cols[8]; // e.g. "*:445" or "127.0.0.1:5432"
            var portStr = addressField.Split(':').LastOrDefault();
            if (portStr is null || !int.TryParse(portStr, out var port)) continue;

            result.Add(new ListeningPort(port, pid, name, null, null));
        }

        return result.DistinctBy(p => p.Port).ToList();
    }
}
