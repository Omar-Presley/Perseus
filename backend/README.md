# Project Perseus (C#/.NET core)

**P**owerShell **E**ndpoint **R**eview and **S**ecurity **E**valuation
**U**tility **S**uite — now a cross-platform C#/.NET application. The name
stays; the "PowerShell" in the acronym is now history rather than the
implementation.

## Read this before anything else

**None of this has been compiled or run.** The sandbox this was written in
has no .NET SDK, and installing one is blocked by the same network
restriction that stops it downloading anything else — confirmed with a real
`apt-get install dotnet-sdk-8.0`, which failed on `403 Forbidden` fetching
from Ubuntu's own security repo. Every `.cs` file here is hand-written
against well-documented .NET APIs and, where possible, checked against real
command output:

- **Linux**: the parsing logic (`/proc/net/tcp` format, `dpkg -l` columns,
  `getent group` fields, `lsblk -J` shape) was verified against actual
  output from this Linux sandbox before being written into C#. The
  Linux-specific tools referenced (`ufw`, `mokutil`, `aa-status`, `getenforce`,
  `fail2ban-client`) mostly aren't installed in this minimal container, so
  the graceful "tool not found -> Unknown" paths are exercised, but the
  "tool is present and working" paths are not.
- **Windows**: registry keys and WMI classes match the same ones the
  PowerShell version used successfully (this is a direct port, not new
  guesses) - carrying over evidence of correctness rather than
  reintroducing risk. `netstat`/`tasklist`/`schtasks` output formats are
  standard and stable across Windows versions but weren't re-verified here.
- **macOS**: entirely unverified. `fdesetup`, `spctl`, `csrutil`, the
  `ApplicationFirewall` helper, and `dscl` are standard, long-documented
  Apple tools, but there's no Mac anywhere in this loop to run them against.

**Build and run this on a real machine with the .NET 8 SDK before trusting
any of it.** `dotnet build` will surface anything wrong far faster than
further review here would.

## What changed from the PowerShell version, and why

- **Real DLLs.** Each module (`Perseus.Reporting`, `Perseus.Audit`,
  `Perseus.Network`, `Perseus.Cve`) is now a genuine C# class library that
  compiles to an actual `.dll` — not a script with a relabeled extension.
- **A real EXE.** `Perseus.Cli` compiles to `PERSEUS.exe` (Windows) or
  `PERSEUS` (Linux/macOS) via `dotnet publish`.
- **C# over native C.** Avalonia (the GUI you mentioned building later) is a
  .NET/C# framework. A C# core means the future GUI project references
  these same DLLs directly, with zero interop layer. A native-C core would
  have needed a P/Invoke or C++/CLI bridge to reach Avalonia later, for no
  offsetting benefit - and would have made the Windows-specific checks
  (WMI, Task Scheduler) considerably more painful to write correctly.
- **The OS-dependent install feature is real.** `PackageManager.cs`
  dispatches to `winget` / `softwareupdate` + `brew` / `apt` based on the
  detected platform - see the "Cross-platform mapping" section below for
  what's implemented on each OS and what isn't yet.
- **One check dropped, deliberately.** The old "PowerShell Logging /
  Execution Policy" check doesn't have a meaningful equivalent for a
  compiled binary - there's no execution policy or script-block logging
  concept for an EXE. It's gone rather than kept as a check that would
  silently report on the wrong thing.

## Solution layout

```
PERSEUS-CS/
├── PERSEUS.sln
├── src/
│   ├── Perseus.Cli/          -> builds PERSEUS.exe (the entry point / menu)
│   ├── Perseus.Reporting/    -> Perseus.Reporting.dll (findings, scoring, HTML/JSON/CSV export)
│   ├── Perseus.Audit/        -> Perseus.Audit.dll (per-OS hardening checks, package manager, config)
│   ├── Perseus.Network/      -> Perseus.Network.dll (listening ports + process/service attribution)
│   └── Perseus.Cve/          -> Perseus.Cve.dll (NVD/CPE-based vulnerability cross-reference)
├── config/
│   ├── settings.json
│   └── signatures.json
├── reports/                  (generated reports land here)
├── logs/
├── docs/
└── LICENSE.txt
```

Dependency direction is a clean DAG - `Reporting` has no project references;
`Audit` depends on `Reporting`; `Network` and `Cve` depend on `Audit` +
`Reporting`; `Cli` depends on all four. No cycles.

## Building

```bash
cd PERSEUS-CS
dotnet build                      # sanity check - this is the step that will catch anything wrong

# Publish a real, self-contained executable for your platform:
dotnet publish src/Perseus.Cli -c Release -r win-x64   --self-contained -p:PublishSingleFile=true
dotnet publish src/Perseus.Cli -c Release -r osx-x64   --self-contained -p:PublishSingleFile=true
dotnet publish src/Perseus.Cli -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true
```

Copy `config/` next to the published executable (or let it generate
defaults on first run - `ConfigLoader` writes `settings.json`/
`signatures.json` if they don't exist, same behavior as the PowerShell
version).

Or just run it directly during development without publishing:

```bash
dotnet run --project src/Perseus.Cli
```

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

Known gaps, called out rather than silently shipped:

- **AppX/MSIX packages** (Windows Store apps) aren't enumerated. The
  PowerShell version used `Get-AppxPackage`; the native .NET equivalent
  needs the WinRT `Windows.Management.Deployment.PackageManager` API via
  CsWinRT projections, which isn't wired up here. Shelling out to
  `powershell.exe -Command "Get-AppxPackage | ConvertTo-Json"` would work
  as a pragmatic bridge if this matters to you - not done by default since
  it re-introduces a PowerShell dependency into a project whose whole point
  was moving off one.
- **macOS `/Applications` entries** show version `"unknown"` unless also
  tracked by Homebrew - reading the real version needs `Info.plist`
  parsing (`CFBundleShortVersionString`), which needs a plist library this
  project doesn't reference yet.
- **RHEL/Fedora/Arch** aren't covered on Linux - only the `apt`-based
  family, matching what was actually asked for.
- **macOS/Linux persistence checks** (login items, LaunchAgents/daemons,
  cron, systemd timers) aren't implemented - the Windows persistence check
  ported over; the other two platforms' equivalents didn't.

## License

See `LICENSE.txt` — placeholder MIT, same as before; review/replace before
distributing.
