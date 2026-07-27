# Project Perseus (C#/.NET core)

██████╗ ███████╗██████╗ ███████╗███████╗██╗   ██╗███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝
██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║   ██║███████╗
██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║   ██║╚════██║
██║     ███████╗██║  ██║███████║███████╗╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝

 ║ Proactive Endpoint Review and Security Evaluation   ║
                   Utility Suite   

A cross-platform C#/.NET application. 

## Cross-platform mapping - what's implemented, what isn't

| Concern | Windows | macOS | Linux |
|---|---|---|---|
| Package upgrades | `winget` ✅ | `softwareupdate -l` (OS) + `brew outdated` (apps) ✅ | `apt` ✅ |
| Disk encryption | BitLocker (WMI) ✅ | FileVault (`fdesetup`) ✅ | LUKS (`lsblk`) ✅ |
| Firewall | `netsh advfirewall` ✅ | Application Firewall (`socketfilterfw`) ✅ | ufw ✅ / firewalld ✅ / raw iptables-only ❌ |
| App-execution gatekeeping | SmartScreen (registry) ✅ | Gatekeeper (`spctl`) ✅ | — (no direct analogue) |
| System integrity | VBS/Cred Guard/HVCI (WMI) ✅ | SIP (`csrutil`) ✅ | AppArmor (`aa-status`) ✅ / SELinux (`getenforce`) ✅ |
| Remote access | RDP (registry) ✅ | — (not implemented) | SSH root login (`sshd_config`) ✅ |
| Local admin | `net localgroup` ✅ | admin group (`dscl`) ✅ | sudo/wheel group (`getent`) ✅ |
| Persistence | Run keys, Startup, scheduled tasks, unquoted paths ✅ | — (not implemented) | — (not implemented - cron/systemd timers would be the equivalent) |
| Software inventory | Registry + winget ✅ (AppX dropped - see below) | Homebrew + `/Applications` (version "unknown" for non-brew apps - see below) | `dpkg` (Debian/Ubuntu only - RPM/pacman not implemented) |

Proactive Endpoint Review &amp; Security Evaluation Utility Suite  - Perseus reviews the security posture of this machine end to end. It inspects operating system hardening, accounts, network exposure, and installed software, then distills everything into a single risk score and severity breakdown you can act on immediately.
