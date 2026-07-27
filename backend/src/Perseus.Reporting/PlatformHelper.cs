using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Perseus.Reporting;

public enum Platform { Windows, MacOs, Linux, Unknown }

public static class PlatformHelper
{
    [DllImport("libc")]
    private static extern uint geteuid();

    public static Platform Current
    {
        get
        {
            if (OperatingSystem.IsWindows()) return Platform.Windows;
            if (OperatingSystem.IsMacOS()) return Platform.MacOs;
            if (OperatingSystem.IsLinux()) return Platform.Linux;
            return Platform.Unknown;
        }
    }

    /// <summary>
    /// True if running elevated: Administrator on Windows, effective root
    /// (euid 0) on Linux/macOS. Several checks degrade gracefully without
    /// this rather than failing outright, same as the PowerShell version.
    /// </summary>
    public static bool IsElevated()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            return geteuid() == 0;
        }
        catch
        {
            // If we can't even determine elevation, assume the least-privileged case
            // so callers show the "some checks may be limited" warning rather than
            // silently proceeding as if elevated.
            return false;
        }
    }
}
