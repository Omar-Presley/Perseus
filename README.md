# Perseus

**P**roactive **E**ndpoint **R**eview and **S**ecurity **E**valuation **U**tility **S**uite

Perseus is a cross-platform desktop application that reviews the security posture of a machine end to end: operating system hardening, user accounts, firewall and encryption settings, patch status, and installed software - then distills the results into a single risk score and severity breakdown.

## What it does

- **Full audit** - checks firewall configuration and remote-access exposure (RDP/SSH/SMB), disk encryption, account and privilege hygiene, persistence mechanisms (startup entries, scheduled tasks), modern platform protections (Secure Boot, Credential Guard, Gatekeeper, SIP, and similar), and patch/software currency, tailored to whichever OS it's running on (Windows, Linux, or macOS).
- **Network inspection** - inventories every listening port and flags the ones commonly associated with risk.
- **CVE cross-reference** - checks installed software against public vulnerability data.
- **AI Assistant** - explains any finding in plain language and gives step-by-step remediation guidance for the current OS. Advisory only; it never runs anything on its own.
- **Remediation** - applies simple package upgrades directly through the OS's own package manager (winget/apt/brew), behind an explicit confirmation step.
- **Reporting** - exports findings as HTML, JSON, or CSV.

## Installing

Grab the latest installer from the [Releases](../../releases) page and run `PerseusSetup.exe`. It installs per-user (no admin required), adds a Start Menu entry, and registers a normal uninstaller.

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

## License

MIT - see [LICENSE.txt](LICENSE.txt).
