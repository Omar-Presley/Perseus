# Perseus

# Goal of this Project

My main goal in this project was to test the capabilities of AI, and the read-only security functionalities of PowerShell. Through this project I weas able to have a better understanding 
of how applications can be deployed and installed across four different systems (e.g., Windows, Linux, Silicon Mac, and Intel Mac). This application can be installed and used for reverse engineering, and/or security testing. It will also most-likely show up in one of my future projects where I reverse engineer or test applications in different languages. Nonetheless, it does still work and can help in finding vulnerabilities and risk indicators for personnel who are newer to IT or system analysis. 


**P**roactive **E**ndpoint **R**eview and **S**ecurity **E**valuation **U**tility **S**uite

Perseus is a cross-platform desktop application that reviews the security posture of a machine end to end: operating system hardening, user accounts, firewall and encryption settings, patch status, and installed software - then distills the results into a single risk score and severity breakdown.

## What it does

- **Full audit** - checks firewall configuration and remote-access exposure (RDP/SSH/SMB), disk encryption, account and privilege hygiene, persistence mechanisms (startup entries, scheduled tasks), modern platform protections (Secure Boot, Credential Guard, Gatekeeper, SIP, and similar), and patch/software currency, tailored to whichever OS it's running on (Windows, Linux, or macOS).
- **Network inspection** - inventories every listening port and flags the ones commonly associated with risk.
- **CVE cross-reference** - checks installed software against public vulnerability data.
- **AI Assistant** - explains any finding in plain language and gives step-by-step remediation guidance for the current OS. Advisory only; it never runs anything on its own.
- **Remediation** - applies simple package upgrades directly through the OS's own package manager (winget/apt/brew), behind an explicit confirmation step.
- **Reporting** - exports findings as HTML, JSON, or CSV.

Note on the Network tab: **Refresh Network** re-scans currently listening ports on demand (via `netstat`/`/proc/net/tcp`/`lsof` depending on OS) without running a full audit or touching your risk score - a lighter-weight check than **Run Full Audit**, which does the same port scan as one step among many and records the results as findings.

## Installing

Grab the latest build for your platform from the [Releases](../../releases) page:

- **Windows** - `PerseusSetup.exe`. Installs per-user (no admin required), adds a Start Menu entry, and registers a normal uninstaller.
- **macOS** - `Perseus-macOS-arm64.zip` (Apple Silicon) or `Perseus-macOS-x64.zip` (Intel). Unzip, then right-click `Perseus.app` -> Open the first time (it's ad-hoc signed but not notarized, so Gatekeeper will still flag it as from an unidentified developer).
- **Linux** - `Perseus-linux-x64.tar.gz`. Extract and run `./Perseus`, or see the included `README.txt` for adding a desktop menu entry.

Releases are built automatically by [`.github/workflows/release.yml`](.github/workflows/release.yml) whenever a version tag (`vX.Y.Z`) is pushed - see "Cutting a release" below.

# Note: There will probably not be another release unless I manually build a new applications in a language I 100% know and use. The application is mainly for learning purposes, AI capability testing, and to be reverse engineering and/or pentested.

## Repository layout

```
Perseus.UI/            the desktop application (Avalonia UI, MVVM)
backend/                the audit/network/CVE/reporting engine, and the original CLI
installer/              Inno Setup script used to build PerseusSetup.exe
```

`Perseus.UI`'s project references the four libraries under `backend/src/` directly, so a single clone of this repository is all that's needed to build.

## Building from source

Requires the .NET SDK.

```
dotnet build Perseus.csproj
```

To produce the same self-contained build the installer packages:

```
dotnet publish -c Release -p:PublishProfile=win-x64
```

Then compile the installer (requires [Inno Setup](https://jrsoftware.org/isinfo.php)):

```
iscc installer\Perseus.iss
```

## Cutting a release

Push a tag matching `vX.Y.Z` and CI builds and publishes all three platforms automatically:

```
git tag v1.0.0
git push origin v1.0.0
```

This builds the Windows installer, ad-hoc-signs and zips both macOS architectures, packages the Linux tarball, and attaches all of them (plus a `SHA256SUMS.txt`) to a new GitHub Release. You can also trigger the same build manually from the Actions tab (`workflow_dispatch`) to sanity-check it without publishing a release.

## License

MIT - see [LICENSE.txt](LICENSE.txt).
