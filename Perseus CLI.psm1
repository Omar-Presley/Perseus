#Requires -Version 5.1
<#
.SYNOPSIS
    Project Perseus - PowerShell Endpoint Review and Security Evaluation
    Utility Suite. A defensive configuration & patch-posture scanner.

.DESCRIPTION
    Scans the local Windows host for common security misconfigurations
    (Defender, Firewall, BitLocker, UAC, SMB, RDP, PowerShell logging,
    local admin accounts, exposed listening ports, missing updates,
    modern hardening features, persistence artifacts, installed software
    inventory) and produces a risk score plus an HTML report. Optionally
    cross-references installed software against the public NVD CVE
    database via CPE version matching, for awareness (informational only -
    this is NOT an exploitation tool).

.NOTES
    Project  : Project Perseus (P.E.R.S.E.U.S.)
    Author   : Omar Presley
    Version  : 1.0
    Run as   : Administrator (recommended - some checks are limited without it)

.EXAMPLE
    .\Start-Perseus.ps1
#>

[CmdletBinding()]
param(
    [switch]$NoBanner,
    [switch]$Transcript
)

$ErrorActionPreference = 'SilentlyContinue'
$Script:Findings = New-Object System.Collections.Generic.List[Object]
$Script:ReportDir = Join-Path $PSScriptRoot 'Reports'
if (-not (Test-Path $Script:ReportDir)) { New-Item -ItemType Directory -Path $Script:ReportDir | Out-Null }

if ($Transcript) {
    $txPath = Join-Path $Script:ReportDir "Perseus_Transcript_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').txt"
    try { Start-Transcript -Path $txPath -Append | Out-Null } catch { }
}

# ---------------------------------------------------------------------------
# region: Configuration
# ---------------------------------------------------------------------------

function Get-AuditConfig {
    $configPath = Join-Path $PSScriptRoot 'settings.json'
    $default = [PSCustomObject]@{
        RiskyPorts = [ordered]@{
            '21'   = 'FTP'
            '22'   = 'SSH'
            '23'   = 'Telnet'
            '135'  = 'RPC'
            '139'  = 'NetBIOS'
            '445'  = 'SMB'
            '3389' = 'RDP'
            '5985' = 'WinRM HTTP'
            '5986' = 'WinRM HTTPS'
        }
        SoftwareWatchlist = @('Java','Adobe Acrobat','Adobe Reader','WinRAR','7-Zip','VNC','TeamViewer','Flash')
        CveWatchlistPattern = 'Chrome|Firefox|Edge|Java|Adobe|OpenSSL|VLC|7-Zip|WinRAR|Zoom|Putty|Notepad\+\+'
        MaxCveTargets = 12
        NvdApiKey = ''
        NvdDelayMs = 700
        UpdateStalenessDays = 60
        MaxAdminAccounts = 3
    }

    if (Test-Path $configPath) {
        try {
            $userConfig = Get-Content $configPath -Raw | ConvertFrom-Json
            foreach ($prop in $userConfig.PSObject.Properties) {
                $default | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
            }
            Write-Host "  [i] Loaded settings.json" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [!] settings.json found but could not be parsed - using defaults" -ForegroundColor Yellow
        }
    } else {
        try {
            $default | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding UTF8
        } catch { }
    }
    return $default
}

$Script:Config = Get-AuditConfig

# ---------------------------------------------------------------------------
# region: Helpers
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Name,
        [ValidateSet('Good','Warning','Bad','Info','Unknown')][string]$Status,
        [string]$Detail,
        [string]$Recommendation,
        [ValidateSet('Low','Medium','High','Critical','Info')][string]$Severity = 'Info',
        [switch]$InternetExposed
    )
    $Script:Findings.Add([PSCustomObject]@{
        Category        = $Category
        Name            = $Name
        Status          = $Status
        Severity        = $Severity
        Detail          = $Detail
        Recommendation  = $Recommendation
        InternetExposed = [bool]$InternetExposed
        Timestamp       = Get-Date
    })
}

function Write-Status {
    param([string]$Symbol, [string]$Text, [string]$Color = 'White')
    Write-Host "  [$Symbol] " -ForegroundColor $Color -NoNewline
    Write-Host $Text
}

function Show-Line { Write-Host ('-' * 70) -ForegroundColor DarkGray }

function Show-Banner {
    if ($NoBanner) { return }
    Clear-Host
    $banner = @"
██████╗ ███████╗██████╗ ███████╗███████╗██╗   ██╗███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝
██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║   ██║███████╗
██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║   ██║╚════██║
██║     ███████╗██║  ██║███████║███████╗╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝

 ║ Proactive Endpoint Review and Security Evaluation   ║
                   Utility Suite   

Version 1.0
"@
    Write-Host $banner -ForegroundColor Cyan
    Show-Line
    if (-not (Test-IsAdmin)) {
        Write-Host "  [!] Not running as Administrator - some checks will be limited." -ForegroundColor Yellow
    } else {
        Write-Host "  [i] Running with Administrator privileges." -ForegroundColor Green
    }
    Write-Host "  [i] Host: $env:COMPUTERNAME   User: $env:USERNAME   Date: $(Get-Date)" -ForegroundColor DarkGray
    Show-Line
}

function Get-SeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 25 }
        'High'     { 15 }
        'Medium'   { 8 }
        'Low'      { 3 }
        default    { 0 }
    }
}

function Get-RiskScore {
    # Deductions are grouped per category first, then summed, so a pile of
    # low-severity findings in one bucket (e.g. ten Info-level software
    # entries) can't silently outweigh a single unrelated Critical finding
    # in another bucket. Internet-exposed findings (open RDP/SMB/WinRM,
    # firewall gaps) get a 1.25x multiplier since they're reachable without
    # local access first.
    $byCategory = $Script:Findings | Group-Object Category
    $totalDeduction = 0

    foreach ($group in $byCategory) {
        $categoryDeduction = 0
        foreach ($f in $group.Group) {
            $weight = 0
            if ($f.Status -eq 'Bad') { $weight = Get-SeverityWeight $f.Severity }
            elseif ($f.Status -eq 'Warning') { $weight = [math]::Ceiling((Get-SeverityWeight $f.Severity) / 2) }
            elseif ($f.Status -eq 'Unknown') { $weight = 2 }  # small penalty for "couldn't verify"

            if ($f.InternetExposed) { $weight = [math]::Round($weight * 1.25) }
            $categoryDeduction += $weight
        }
        # Cap any single category's contribution so one noisy area can't
        # single-handedly drag the score to zero.
        if ($categoryDeduction -gt 40) { $categoryDeduction = 40 }
        $totalDeduction += $categoryDeduction
    }

    $score = 100 - $totalDeduction
    if ($score -lt 0) { $score = 0 }
    return $score
}

function Get-RiskLevel {
    param([int]$Score)
    if ($Score -ge 85) { return 'LOW' }
    elseif ($Score -ge 65) { return 'MEDIUM' }
    elseif ($Score -ge 40) { return 'HIGH' }
    else { return 'CRITICAL' }
}

# endregion

# ---------------------------------------------------------------------------
# region: Individual audit checks
# ---------------------------------------------------------------------------

function Invoke-WindowsUpdateCheck {
    Write-Host "`n[*] Checking Windows Update / patch status..." -ForegroundColor Cyan
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $build = $os.BuildNumber
        $caption = $os.Caption

        Add-Finding -Category 'Patching' -Name 'OS Version' -Status 'Info' `
            -Detail "$caption (Build $build)" -Recommendation 'N/A' -Severity 'Info'
        Write-Status -Symbol 'i' -Text "OS: $caption (Build $build)" -Color Cyan

        $unsupported = @('Windows 7', 'Windows 8', 'Windows Vista', 'Windows XP', 'Windows Server 2008')
        $isUnsupported = $unsupported | Where-Object { $caption -like "*$_*" }
        if ($isUnsupported) {
            Add-Finding -Category 'Patching' -Name 'Unsupported OS' -Status 'Bad' `
                -Detail "$caption is end-of-life." -Recommendation 'Upgrade to a supported OS version.' -Severity 'Critical'
            Write-Status -Symbol 'X' -Text 'Operating system is unsupported / end-of-life' -Color Red
        }

        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
        if ($hotfixes) {
            $last = $hotfixes | Select-Object -First 1
            $daysSince = if ($last.InstalledOn) { (New-TimeSpan -Start $last.InstalledOn -End (Get-Date)).Days } else { $null }
            Add-Finding -Category 'Patching' -Name 'Last Update Installed' -Status 'Info' `
                -Detail "$($last.HotFixID) on $($last.InstalledOn)" -Recommendation 'N/A' -Severity 'Info'
            Write-Status -Symbol 'i' -Text "Last KB installed: $($last.HotFixID) ($($last.InstalledOn))" -Color Cyan

            $staleThreshold = [int]$Script:Config.UpdateStalenessDays
            if ($daysSince -and $daysSince -gt $staleThreshold) {
                Add-Finding -Category 'Patching' -Name 'Update Recency' -Status 'Warning' `
                    -Detail "No updates installed in $daysSince days (threshold: $staleThreshold)." `
                    -Recommendation 'Run Windows Update / check WSUS connectivity.' -Severity 'Medium'
                Write-Status -Symbol '!' -Text "No updates in $daysSince days" -Color Yellow
            } else {
                Write-Status -Symbol 'OK' -Text 'Update cadence looks reasonable' -Color Green
            }
        } else {
            Add-Finding -Category 'Patching' -Name 'Update History' -Status 'Warning' `
                -Detail 'Could not enumerate hotfix history.' -Recommendation 'Verify Windows Update service is running.' -Severity 'Low'
        }

        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $result = $searcher.Search("IsInstalled=0 and Type='Software'")
            $pending = $result.Updates.Count
            if ($pending -gt 0) {
                Add-Finding -Category 'Patching' -Name 'Pending Updates' -Status 'Bad' `
                    -Detail "$pending update(s) pending installation." -Recommendation 'Install pending Windows updates.' -Severity 'High'
                Write-Status -Symbol 'X' -Text "$pending pending update(s) found" -Color Red
            } else {
                Add-Finding -Category 'Patching' -Name 'Pending Updates' -Status 'Good' `
                    -Detail 'No pending updates detected.' -Recommendation 'N/A' -Severity 'Info'
                Write-Status -Symbol 'OK' -Text 'No pending updates detected' -Color Green
            }
        } catch {
            Write-Status -Symbol 'i' -Text 'Pending-update search unavailable (COM API blocked/offline)' -Color DarkGray
        }
    } catch {
        Write-Status -Symbol '!' -Text "Update check failed: $_" -Color Yellow
    }
}

function Invoke-LocalAdminCheck {
    Write-Host "`n[*] Checking local administrator accounts..." -ForegroundColor Cyan
    try {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        $adminCount = ($admins | Measure-Object).Count
        Add-Finding -Category 'Accounts' -Name 'Administrator Group Members' -Status 'Info' `
            -Detail ($admins.Name -join ', ') -Recommendation 'N/A' -Severity 'Info'
        Write-Status -Symbol 'i' -Text "Local Administrators group has $adminCount member(s)" -Color Cyan

        $maxAdmins = [int]$Script:Config.MaxAdminAccounts
        if ($adminCount -gt $maxAdmins) {
            Add-Finding -Category 'Accounts' -Name 'Excess Admins' -Status 'Warning' `
                -Detail "$adminCount accounts have local admin rights (threshold: $maxAdmins)." `
                -Recommendation 'Apply least-privilege - remove unnecessary admin members.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text "$adminCount accounts hold admin rights (review recommended)" -Color Yellow
        }

        $builtinAdmin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        if ($builtinAdmin -and $builtinAdmin.Enabled) {
            Add-Finding -Category 'Accounts' -Name 'Built-in Administrator' -Status 'Warning' `
                -Detail 'Built-in Administrator account is enabled.' `
                -Recommendation 'Disable the built-in Administrator account if not required.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text 'Built-in Administrator account is ENABLED' -Color Yellow
        } elseif ($builtinAdmin) {
            Write-Status -Symbol 'OK' -Text 'Built-in Administrator account is disabled' -Color Green
        }

        $users = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($u in $users) {
            if ($u.Enabled -and $u.PasswordRequired -eq $false) {
                Add-Finding -Category 'Accounts' -Name "Blank/Optional Password: $($u.Name)" -Status 'Bad' `
                    -Detail "$($u.Name) does not require a password." -Recommendation 'Require strong passwords for all local accounts.' -Severity 'High'
                Write-Status -Symbol 'X' -Text "$($u.Name): password not required" -Color Red
            }
            if ($u.Enabled -and $u.PasswordExpires -eq $null -and $u.PasswordRequired) {
                Add-Finding -Category 'Accounts' -Name "Password Never Expires: $($u.Name)" -Status 'Warning' `
                    -Detail "$($u.Name) has a non-expiring password." -Recommendation 'Enforce password expiration policy.' -Severity 'Low'
            }
        }
    } catch {
        Write-Status -Symbol '!' -Text 'Local admin enumeration requires elevation' -Color Yellow
    }
}

function Invoke-DefenderCheck {
    Write-Host "`n[*] Checking Windows Defender health..." -ForegroundColor Cyan
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop

        if (-not $mp.RealTimeProtectionEnabled) {
            Add-Finding -Category 'Defender' -Name 'Real-Time Protection' -Status 'Bad' `
                -Detail 'Real-time protection is disabled.' -Recommendation 'Enable real-time protection immediately.' -Severity 'Critical'
            Write-Status -Symbol 'X' -Text 'Real-time protection DISABLED' -Color Red
        } else {
            Write-Status -Symbol 'OK' -Text 'Real-time protection enabled' -Color Green
        }

        if (-not $mp.IsTamperProtected) {
            Add-Finding -Category 'Defender' -Name 'Tamper Protection' -Status 'Warning' `
                -Detail 'Tamper Protection is off.' -Recommendation 'Enable Tamper Protection in Windows Security.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text 'Tamper Protection disabled' -Color Yellow
        } else {
            Write-Status -Symbol 'OK' -Text 'Tamper Protection enabled' -Color Green
        }

        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs -and $prefs.MAPSReporting -eq 0) {
            Add-Finding -Category 'Defender' -Name 'Cloud Protection' -Status 'Warning' `
                -Detail 'Cloud-delivered protection (MAPS) is disabled.' -Recommendation 'Enable cloud protection for faster signature response.' -Severity 'Low'
            Write-Status -Symbol '!' -Text 'Cloud-delivered protection disabled' -Color Yellow
        }

        if ($prefs -and $prefs.EnableControlledFolderAccess -eq 0) {
            Write-Status -Symbol 'i' -Text 'Controlled Folder Access not enabled (optional hardening)' -Color DarkGray
        }

        $sigAge = (Get-Date) - $mp.AntivirusSignatureLastUpdated
        if ($sigAge.Days -gt 7) {
            Add-Finding -Category 'Defender' -Name 'Signature Age' -Status 'Bad' `
                -Detail "Signatures are $($sigAge.Days) days old." -Recommendation 'Update Defender signatures.' -Severity 'High'
            Write-Status -Symbol 'X' -Text "Signatures are $($sigAge.Days) days old" -Color Red
        } else {
            Write-Status -Symbol 'OK' -Text "Signatures up to date ($($sigAge.Days)d old)" -Color Green
        }
    } catch {
        Write-Status -Symbol '!' -Text 'Windows Defender cmdlets unavailable (3rd-party AV or Defender disabled)' -Color Yellow
        Add-Finding -Category 'Defender' -Name 'Defender Status' -Status 'Warning' `
            -Detail 'Get-MpComputerStatus failed - Defender may be disabled or replaced.' `
            -Recommendation 'Confirm an active, up-to-date endpoint protection product is installed.' -Severity 'Medium'
    }
}

function Invoke-FirewallCheck {
    Write-Host "`n[*] Checking Windows Firewall..." -ForegroundColor Cyan
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            if (-not $p.Enabled) {
                Add-Finding -Category 'Firewall' -Name "$($p.Name) Profile" -Status 'Bad' -InternetExposed `
                    -Detail "$($p.Name) firewall profile is disabled." -Recommendation 'Enable the firewall for all profiles.' -Severity 'High'
                Write-Status -Symbol 'X' -Text "$($p.Name) profile: DISABLED" -Color Red
            } else {
                Write-Status -Symbol 'OK' -Text "$($p.Name) profile: enabled" -Color Green
            }
            if ($p.LogAllowed -eq 'False' -and $p.LogBlocked -eq 'False') {
                Add-Finding -Category 'Firewall' -Name "$($p.Name) Logging" -Status 'Warning' `
                    -Detail "$($p.Name) profile logging disabled." -Recommendation 'Enable firewall logging for forensic visibility.' -Severity 'Low'
            }
        }

        $allowAllRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -notmatch 'Core Networking|mDNS|Discovery' }
        Add-Finding -Category 'Firewall' -Name 'Inbound Allow Rules' -Status 'Info' `
            -Detail "$($allowAllRules.Count) enabled inbound allow rule(s)." -Recommendation 'Periodically review inbound allow rules.' -Severity 'Info'
        Write-Status -Symbol 'i' -Text "$($allowAllRules.Count) inbound allow rule(s) enabled (review periodically)" -Color Cyan
    } catch {
        Write-Status -Symbol '!' -Text 'Could not query firewall profiles' -Color Yellow
    }
}

function Invoke-RdpCheck {
    Write-Host "`n[*] Checking Remote Desktop configuration..." -ForegroundColor Cyan
    $rdpKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $nlaKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    try {
        $deny = (Get-ItemProperty -Path $rdpKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($deny -eq 0) {
            Add-Finding -Category 'RDP' -Name 'RDP Enabled' -Status 'Warning' -InternetExposed `
                -Detail 'Remote Desktop is enabled.' -Recommendation 'Disable RDP if not needed, or restrict via firewall/VPN.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text 'RDP is ENABLED' -Color Yellow

            $nla = (Get-ItemProperty -Path $nlaKey -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
            if ($nla -eq 0) {
                Add-Finding -Category 'RDP' -Name 'Network Level Authentication' -Status 'Bad' -InternetExposed `
                    -Detail 'NLA is disabled for RDP.' -Recommendation 'Enable Network Level Authentication.' -Severity 'High'
                Write-Status -Symbol 'X' -Text 'Network Level Authentication (NLA) DISABLED' -Color Red
            } else {
                Write-Status -Symbol 'OK' -Text 'NLA enabled' -Color Green
            }

            $enc = (Get-ItemProperty -Path $nlaKey -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel
            if ($enc -lt 3) {
                Add-Finding -Category 'RDP' -Name 'RDP Encryption Level' -Status 'Warning' `
                    -Detail "MinEncryptionLevel = $enc (below High)." -Recommendation 'Set RDP encryption level to High (3).' -Severity 'Medium'
            }
        } else {
            Write-Status -Symbol 'OK' -Text 'RDP is disabled' -Color Green
            Add-Finding -Category 'RDP' -Name 'RDP Enabled' -Status 'Good' -Detail 'RDP disabled.' -Recommendation 'N/A' -Severity 'Info'
        }
    } catch {
        Write-Status -Symbol '!' -Text 'Could not read RDP registry keys' -Color Yellow
    }
}

function Invoke-SmbCheck {
    Write-Host "`n[*] Checking SMB configuration..." -ForegroundColor Cyan
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') {
            Add-Finding -Category 'SMB' -Name 'SMBv1' -Status 'Bad' -InternetExposed `
                -Detail 'SMBv1 protocol is enabled.' -Recommendation 'Disable SMBv1 (vulnerable to EternalBlue-class exploits).' -Severity 'Critical'
            Write-Status -Symbol 'X' -Text 'SMBv1 is ENABLED (legacy, high risk)' -Color Red
        } else {
            Write-Status -Symbol 'OK' -Text 'SMBv1 disabled/not installed' -Color Green
        }

        $smbConf = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($smbConf) {
            if (-not $smbConf.RequireSecuritySignature) {
                Add-Finding -Category 'SMB' -Name 'SMB Signing' -Status 'Warning' `
                    -Detail 'SMB signing is not required.' -Recommendation 'Require SMB signing to prevent relay attacks.' -Severity 'Medium'
                Write-Status -Symbol '!' -Text 'SMB signing not required' -Color Yellow
            } else {
                Write-Status -Symbol 'OK' -Text 'SMB signing required' -Color Green
            }
            if ($smbConf.EnableSMB1Protocol) {
                Write-Status -Symbol 'X' -Text 'SMB server config still allows SMB1' -Color Red
            }
        }

        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Add-Finding -Category 'SMB' -Name 'Guest Account' -Status 'Bad' `
                -Detail 'Guest account is enabled.' -Recommendation 'Disable the Guest account.' -Severity 'High'
            Write-Status -Symbol 'X' -Text 'Guest account is ENABLED' -Color Red
        }
    } catch {
        Write-Status -Symbol '!' -Text 'SMB check incomplete (requires elevation)' -Color Yellow
    }
}

function Invoke-PowerShellLoggingCheck {
    Write-Host "`n[*] Checking PowerShell logging & execution policy..." -ForegroundColor Cyan
    $ep = Get-ExecutionPolicy
    Add-Finding -Category 'PowerShell' -Name 'Execution Policy' -Status 'Info' -Detail "$ep" -Recommendation 'N/A' -Severity 'Info'
    if ($ep -eq 'Unrestricted' -or $ep -eq 'Bypass') {
        Add-Finding -Category 'PowerShell' -Name 'Execution Policy Risk' -Status 'Warning' `
            -Detail "Execution policy is $ep." -Recommendation 'Use RemoteSigned or AllSigned.' -Severity 'Medium'
        Write-Status -Symbol '!' -Text "Execution policy is permissive: $ep" -Color Yellow
    } else {
        Write-Status -Symbol 'OK' -Text "Execution policy: $ep" -Color Green
    }

    $sbLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sbLog = (Get-ItemProperty -Path $sbLogPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($sbLog -ne 1) {
        Add-Finding -Category 'PowerShell' -Name 'Script Block Logging' -Status 'Warning' `
            -Detail 'Script Block Logging not enabled via policy.' -Recommendation 'Enable Script Block Logging for detection/forensics.' -Severity 'Low'
        Write-Status -Symbol '!' -Text 'Script Block Logging not enabled' -Color Yellow
    } else {
        Write-Status -Symbol 'OK' -Text 'Script Block Logging enabled' -Color Green
    }

    $clm = $ExecutionContext.SessionState.LanguageMode
    Write-Status -Symbol 'i' -Text "Current session language mode: $clm" -Color Cyan
}

function Invoke-UacCheck {
    Write-Host "`n[*] Checking User Account Control (UAC)..." -ForegroundColor Cyan
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $enabled = (Get-ItemProperty -Path $key -Name 'EnableLUA' -ErrorAction Stop).EnableLUA
        if ($enabled -eq 0) {
            Add-Finding -Category 'UAC' -Name 'UAC Enabled' -Status 'Bad' `
                -Detail 'UAC is disabled.' -Recommendation 'Enable UAC (EnableLUA=1).' -Severity 'High'
            Write-Status -Symbol 'X' -Text 'UAC is DISABLED' -Color Red
        } else {
            Write-Status -Symbol 'OK' -Text 'UAC enabled' -Color Green
        }

        $secureDesktop = (Get-ItemProperty -Path $key -Name 'PromptOnSecureDesktop' -ErrorAction SilentlyContinue).PromptOnSecureDesktop
        if ($secureDesktop -eq 0) {
            Add-Finding -Category 'UAC' -Name 'Secure Desktop' -Status 'Warning' `
                -Detail 'UAC prompts do not use the secure desktop.' -Recommendation 'Enable "switch to secure desktop" for UAC prompts.' -Severity 'Low'
            Write-Status -Symbol '!' -Text 'Secure Desktop for UAC prompts disabled' -Color Yellow
        }

        $consentPrompt = (Get-ItemProperty -Path $key -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        if ($consentPrompt -eq 0) {
            Add-Finding -Category 'UAC' -Name 'Admin Approval Mode' -Status 'Bad' `
                -Detail 'Admins elevate silently without prompting.' -Recommendation 'Set admin approval mode to prompt for consent/credentials.' -Severity 'High'
            Write-Status -Symbol 'X' -Text 'Admin actions elevate WITHOUT prompting' -Color Red
        }
    } catch {
        Write-Status -Symbol '!' -Text 'Could not read UAC registry keys' -Color Yellow
    }
}

function Invoke-BitLockerCheck {
    Write-Host "`n[*] Checking BitLocker status..." -ForegroundColor Cyan
    try {
        $vols = Get-BitLockerVolume -ErrorAction Stop
        foreach ($v in $vols) {
            if ($v.VolumeType -eq 'OperatingSystem') {
                if ($v.ProtectionStatus -ne 'On') {
                    Add-Finding -Category 'BitLocker' -Name "Drive $($v.MountPoint)" -Status 'Bad' `
                        -Detail "$($v.MountPoint) is not encrypted." -Recommendation 'Enable BitLocker on the OS drive.' -Severity 'High'
                    Write-Status -Symbol 'X' -Text "$($v.MountPoint) NOT encrypted" -Color Red
                } else {
                    Write-Status -Symbol 'OK' -Text "$($v.MountPoint) encrypted ($($v.EncryptionPercentage)%)" -Color Green
                    if (-not $v.KeyProtector -or $v.KeyProtector.Count -eq 0) {
                        Add-Finding -Category 'BitLocker' -Name 'Recovery Key Backup' -Status 'Warning' `
                            -Detail 'No key protectors found.' -Recommendation 'Back up the BitLocker recovery key to AD/Azure AD or a safe location.' -Severity 'Medium'
                    }
                }
            }
        }
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and -not $tpm.TpmPresent) {
            Add-Finding -Category 'BitLocker' -Name 'TPM' -Status 'Warning' `
                -Detail 'No TPM detected.' -Recommendation 'BitLocker without TPM offers weaker protection - consider hardware with TPM 2.0.' -Severity 'Low'
            Write-Status -Symbol '!' -Text 'No TPM present' -Color Yellow
        } elseif ($tpm) {
            Write-Status -Symbol 'OK' -Text "TPM present (Ready: $($tpm.TpmReady))" -Color Green
        }
    } catch {
        Write-Status -Symbol '!' -Text 'BitLocker cmdlets unavailable (not supported on this edition/VM)' -Color Yellow
    }
}

function Invoke-ModernSecurityCheck {
    Write-Host "`n[*] Checking modern Windows security posture (VBS/Credential Guard/Secure Boot/etc.)..." -ForegroundColor Cyan

    # --- Secure Boot ---
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if (-not $sb) {
            Add-Finding -Category 'ModernSecurity' -Name 'Secure Boot' -Status 'Bad' `
                -Detail 'Secure Boot is disabled or unsupported.' -Recommendation 'Enable Secure Boot in firmware/UEFI settings.' -Severity 'High'
            Write-Status -Symbol 'X' -Text 'Secure Boot is DISABLED' -Color Red
        } else {
            Write-Status -Symbol 'OK' -Text 'Secure Boot enabled' -Color Green
        }
    } catch {
        Add-Finding -Category 'ModernSecurity' -Name 'Secure Boot' -Status 'Unknown' `
            -Detail 'Could not determine Secure Boot state (legacy BIOS or access denied).' -Recommendation 'Verify manually in firmware settings.' -Severity 'Low'
        Write-Status -Symbol 'i' -Text 'Secure Boot state unknown (legacy BIOS, or requires elevation)' -Color DarkGray
    }

    # --- VBS / Credential Guard / HVCI via Device Guard WMI class ---
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $vbsRunning = $dg.VirtualizationBasedSecurityStatus -eq 2
        $cgConfigured = $dg.SecurityServicesConfigured -contains 1
        $cgRunning = $dg.SecurityServicesRunning -contains 1
        $hvciRunning = $dg.SecurityServicesRunning -contains 2

        if (-not $vbsRunning) {
            Add-Finding -Category 'ModernSecurity' -Name 'Virtualization-Based Security' -Status 'Warning' `
                -Detail 'VBS is not running.' -Recommendation 'Enable VBS (Core Isolation) if hardware supports it.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text 'VBS not running' -Color Yellow
        } else {
            Write-Status -Symbol 'OK' -Text 'VBS running' -Color Green
        }

        if ($cgConfigured -and -not $cgRunning) {
            Add-Finding -Category 'ModernSecurity' -Name 'Credential Guard' -Status 'Bad' `
                -Detail 'Credential Guard is configured but not running.' -Recommendation 'Investigate why Credential Guard failed to start (hardware/driver compatibility).' -Severity 'High'
            Write-Status -Symbol 'X' -Text 'Credential Guard configured but NOT running' -Color Red
        } elseif ($cgRunning) {
            Write-Status -Symbol 'OK' -Text 'Credential Guard running' -Color Green
        } else {
            Write-Status -Symbol 'i' -Text 'Credential Guard not configured' -Color DarkGray
        }

        if (-not $hvciRunning) {
            Add-Finding -Category 'ModernSecurity' -Name 'Memory Integrity (HVCI)' -Status 'Warning' `
                -Detail 'HVCI/Memory Integrity is not running.' -Recommendation 'Enable Memory Integrity under Windows Security > Device Security.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text 'HVCI (Memory Integrity) not running' -Color Yellow
        } else {
            Write-Status -Symbol 'OK' -Text 'HVCI (Memory Integrity) running' -Color Green
        }
    } catch {
        Add-Finding -Category 'ModernSecurity' -Name 'VBS / Credential Guard / HVCI' -Status 'Unknown' `
            -Detail 'Device Guard WMI class unavailable.' -Recommendation 'Check manually via System Information (msinfo32).' -Severity 'Low'
        Write-Status -Symbol 'i' -Text 'VBS/Credential Guard/HVCI status unavailable on this SKU/VM' -Color DarkGray
    }

    # --- LSA Protection (RunAsPPL) ---
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    try {
        $ppl = (Get-ItemProperty -Path $lsaKey -Name 'RunAsPPL' -ErrorAction Stop).RunAsPPL
        if ($ppl -ne 1) {
            Add-Finding -Category 'ModernSecurity' -Name 'LSA Protection' -Status 'Warning' `
                -Detail 'LSA Protection (RunAsPPL) is not enabled.' -Recommendation 'Enable LSA Protection to harden LSASS against credential dumping.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text 'LSA Protection (RunAsPPL) disabled' -Color Yellow
        } else {
            Write-Status -Symbol 'OK' -Text 'LSA Protection enabled' -Color Green
        }
    } catch {
        Add-Finding -Category 'ModernSecurity' -Name 'LSA Protection' -Status 'Unknown' `
            -Detail 'RunAsPPL value not present/readable.' -Recommendation 'Enable LSA Protection per Microsoft guidance.' -Severity 'Low'
        Write-Status -Symbol 'i' -Text 'LSA Protection value not set (treated as disabled by default)' -Color DarkGray
    }

    # --- WDigest ---
    $wdigestKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $wdigest = (Get-ItemProperty -Path $wdigestKey -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
    if ($wdigest -eq 1) {
        Add-Finding -Category 'ModernSecurity' -Name 'WDigest' -Status 'Bad' `
            -Detail 'WDigest is configured to cache plaintext credentials in memory.' -Recommendation 'Set UseLogonCredential to 0.' -Severity 'High'
        Write-Status -Symbol 'X' -Text 'WDigest plaintext credential caching ENABLED' -Color Red
    } else {
        Write-Status -Symbol 'OK' -Text 'WDigest plaintext credential caching disabled/default' -Color Green
    }

    # --- SmartScreen ---
    $ssKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $ssVal = (Get-ItemProperty -Path $ssKey -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue).EnableSmartScreen
    if ($ssVal -eq 0) {
        Add-Finding -Category 'ModernSecurity' -Name 'SmartScreen' -Status 'Warning' `
            -Detail 'SmartScreen is disabled by policy.' -Recommendation 'Re-enable SmartScreen for app/browser protection.' -Severity 'Medium'
        Write-Status -Symbol '!' -Text 'SmartScreen disabled by policy' -Color Yellow
    } else {
        Write-Status -Symbol 'i' -Text 'SmartScreen not explicitly disabled by policy' -Color DarkGray
    }

    # --- ASR rules (Attack Surface Reduction) ---
    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        $asrCount = ($prefs.AttackSurfaceReductionRules_Ids | Where-Object { $_ }).Count
        if ($asrCount -eq 0) {
            Add-Finding -Category 'ModernSecurity' -Name 'Attack Surface Reduction Rules' -Status 'Warning' `
                -Detail 'No ASR rules configured.' -Recommendation 'Configure ASR rules (e.g. block Office child-process creation, credential stealing) via Defender policy.' -Severity 'Low'
            Write-Status -Symbol '!' -Text 'No ASR rules configured' -Color Yellow
        } else {
            Write-Status -Symbol 'OK' -Text "$asrCount ASR rule(s) configured" -Color Green
        }
    } catch {
        Write-Status -Symbol 'i' -Text 'ASR rule status unavailable' -Color DarkGray
    }

    # --- LAPS presence (local admin password rotation) ---
    $lapsPresent = (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') -or
                   (Get-Module -ListAvailable -Name 'LAPS' -ErrorAction SilentlyContinue) -or
                   (Get-Module -ListAvailable -Name 'AdmPwd.PS' -ErrorAction SilentlyContinue)
    if (-not $lapsPresent) {
        Add-Finding -Category 'ModernSecurity' -Name 'LAPS' -Status 'Info' `
            -Detail 'No LAPS (Local Administrator Password Solution) policy/module detected.' `
            -Recommendation 'On domain-joined fleets, deploy LAPS to rotate local admin passwords.' -Severity 'Info'
        Write-Status -Symbol 'i' -Text 'LAPS not detected (relevant mainly for domain-joined fleets)' -Color DarkGray
    } else {
        Write-Status -Symbol 'OK' -Text 'LAPS policy/module detected' -Color Green
    }
}

function Invoke-PersistenceCheck {
    Write-Host "`n[*] Checking common persistence locations..." -ForegroundColor Cyan

    # --- Run / RunOnce registry keys ---
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $runEntryCount = 0
    foreach ($key in $runKeys) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($props) {
            $entries = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider)$' }
            foreach ($e in $entries) {
                $runEntryCount++
                if ($e.Value -match 'powershell(\.exe)?.*(-enc|-e |EncodedCommand|-w hidden|-windowstyle hidden)' ) {
                    Add-Finding -Category 'Persistence' -Name "Run Key: $($e.Name)" -Status 'Bad' `
                        -Detail "$key\$($e.Name) = $($e.Value)" `
                        -Recommendation 'Investigate this autorun entry - looks like an encoded/hidden PowerShell invocation.' -Severity 'Critical'
                    Write-Status -Symbol 'X' -Text "Suspicious autorun: $($e.Name)" -Color Red
                } elseif ($e.Value -match '\\(Temp|AppData\\Local\\Temp)\\') {
                    Add-Finding -Category 'Persistence' -Name "Run Key: $($e.Name)" -Status 'Warning' `
                        -Detail "$key\$($e.Name) launches from a temp directory: $($e.Value)" `
                        -Recommendation 'Verify legitimacy - execution from temp folders is a common persistence pattern.' -Severity 'Medium'
                    Write-Status -Symbol '!' -Text "Autorun from temp path: $($e.Name)" -Color Yellow
                }
            }
        }
    }
    Add-Finding -Category 'Persistence' -Name 'Run/RunOnce Entries' -Status 'Info' `
        -Detail "$runEntryCount autorun entr(y/ies) across Run/RunOnce keys." -Recommendation 'N/A' -Severity 'Info'
    Write-Status -Symbol 'i' -Text "$runEntryCount total Run/RunOnce entries reviewed" -Color Cyan

    # --- Startup folders ---
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($i in $items) {
                Add-Finding -Category 'Persistence' -Name "Startup Item: $($i.Name)" -Status 'Info' `
                    -Detail "Found in $folder" -Recommendation 'Confirm this startup item is expected.' -Severity 'Info'
            }
            if ($items) { Write-Status -Symbol 'i' -Text "$($items.Count) item(s) in $folder" -Color Cyan }
        }
    }

    # --- Scheduled tasks with suspicious PowerShell actions ---
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
        $suspiciousCount = 0
        foreach ($t in $tasks) {
            foreach ($action in $t.Actions) {
                $cmd = "$($action.Execute) $($action.Arguments)"
                if ($cmd -match 'powershell(\.exe)?' -and $cmd -match '-enc|EncodedCommand|-nop.*-w hidden|IEX|Invoke-Expression|DownloadString') {
                    $suspiciousCount++
                    Add-Finding -Category 'Persistence' -Name "Scheduled Task: $($t.TaskName)" -Status 'Bad' `
                        -Detail "Task '$($t.TaskName)' runs: $cmd" `
                        -Recommendation 'Review this scheduled task - encoded/download-and-execute PowerShell patterns are common malware persistence.' -Severity 'Critical'
                    Write-Status -Symbol 'X' -Text "Suspicious scheduled task: $($t.TaskName)" -Color Red
                }
            }
        }
        Add-Finding -Category 'Persistence' -Name 'Scheduled Tasks Reviewed' -Status 'Info' `
            -Detail "$($tasks.Count) active scheduled task(s) reviewed, $suspiciousCount flagged." -Recommendation 'N/A' -Severity 'Info'
        Write-Status -Symbol 'i' -Text "$($tasks.Count) active scheduled task(s) reviewed ($suspiciousCount flagged)" -Color Cyan
    } catch {
        Write-Status -Symbol '!' -Text 'Could not enumerate scheduled tasks' -Color Yellow
    }

    # --- Unquoted service paths (classic local-privesc vector) ---
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.PathName -match '\.exe'
        }
        $unquoted = $services | Where-Object {
            # Only a real risk if there's a space before .exe in an unquoted path
            $exeIndex = $_.PathName.ToLower().IndexOf('.exe')
            $spaceBefore = $_.PathName.Substring(0, $exeIndex) -match '\s'
            $spaceBefore
        }
        foreach ($s in $unquoted) {
            Add-Finding -Category 'Persistence' -Name "Unquoted Service Path: $($s.Name)" -Status 'Warning' `
                -Detail "$($s.Name): $($s.PathName)" `
                -Recommendation 'Quote the service binary path to prevent path-interception privilege escalation.' -Severity 'Medium'
            Write-Status -Symbol '!' -Text "Unquoted path: $($s.Name)" -Color Yellow
        }
        if (-not $unquoted) { Write-Status -Symbol 'OK' -Text 'No unquoted service paths with embedded spaces found' -Color Green }
    } catch {
        Write-Status -Symbol '!' -Text 'Could not enumerate services for unquoted-path check' -Color Yellow
    }
}

function Get-OwningServiceName {
    param([int]$ProcessId)
    try {
        $svc = Get-CimInstance Win32_Service -Filter "ProcessId=$ProcessId" -ErrorAction Stop | Select-Object -First 1
        if ($svc) { return $svc.Name }
    } catch { }
    return $null
}

function Invoke-NetworkPortCheck {
    Write-Host "`n[*] Checking listening network ports..." -ForegroundColor Cyan

    # Config-driven so the port watchlist can be tuned without editing code.
    $riskyPorts = @{}
    foreach ($prop in $Script:Config.RiskyPorts.PSObject.Properties) { $riskyPorts[[int]$prop.Name] = $prop.Value }

    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Select-Object LocalPort, OwningProcess -Unique

        $enriched = foreach ($l in $listeners) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $svcName = $null
            if ($proc -and $proc.ProcessName -in @('svchost','services')) {
                $svcName = Get-OwningServiceName -ProcessId $l.OwningProcess
            }
            [PSCustomObject]@{
                Port        = $l.LocalPort
                PID         = $l.OwningProcess
                ProcessName = if ($proc) { $proc.ProcessName } else { 'Unknown' }
                Path        = if ($proc) { $proc.Path } else { $null }
                ServiceName = $svcName
            }
        }

        $openRisky = $enriched | Where-Object { $riskyPorts.ContainsKey([int]$_.Port) }
        foreach ($o in $openRisky) {
            $svc = $riskyPorts[[int]$o.Port]
            $owner = if ($o.ServiceName) { "service '$($o.ServiceName)'" }
                     elseif ($o.Path) { $o.Path }
                     else { "$($o.ProcessName) (PID $($o.PID))" }
            Add-Finding -Category 'Network' -Name "Port $($o.Port) ($svc)" -Status 'Warning' -InternetExposed `
                -Detail "$svc listening on port $($o.Port), owned by $owner." `
                -Recommendation "Restrict $svc exposure to trusted networks/VPN only; verify $owner is expected." -Severity 'Medium'
            Write-Status -Symbol '!' -Text "Port $($o.Port) open ($svc) - $owner" -Color Yellow
        }

        Add-Finding -Category 'Network' -Name 'Total Listening Ports' -Status 'Info' `
            -Detail "$($enriched.Count) TCP port(s) listening." -Recommendation 'N/A' -Severity 'Info'
        Write-Status -Symbol 'i' -Text "$($enriched.Count) total listening TCP port(s)" -Color Cyan
        return $enriched
    } catch {
        Write-Status -Symbol '!' -Text 'Could not enumerate TCP listeners' -Color Yellow
        return @()
    }
}

function Invoke-SoftwareInventory {
    Write-Host "`n[*] Enumerating installed software..." -ForegroundColor Cyan
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $classic = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayVersion } |
        Select-Object @{n='DisplayName';e={$_.DisplayName}}, @{n='DisplayVersion';e={$_.DisplayVersion}}, `
                      @{n='Publisher';e={$_.Publisher}}, @{n='Source';e={'Registry'}}

    # AppX/MSIX packages (Store apps) - separate namespace from classic Win32 uninstall keys
    $appx = @()
    try {
        $appx = Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework } | ForEach-Object {
            [PSCustomObject]@{
                DisplayName    = $_.Name
                DisplayVersion = $_.Version.ToString()
                Publisher      = $_.Publisher
                Source         = 'AppX'
            }
        }
    } catch { }

    # winget-managed packages, if the client is present
    $winget = @()
    try {
        $wingetRaw = & winget list --accept-source-agreements 2>$null
        if ($wingetRaw) {
            # Skip header/separator lines; columns are whitespace-aligned, so this is best-effort.
            $dataLines = $wingetRaw | Select-Object -Skip 2 | Where-Object { $_ -match '\S' }
            $winget = foreach ($line in $dataLines) {
                $cols = ($line -split '\s{2,}')
                if ($cols.Count -ge 2) {
                    [PSCustomObject]@{
                        DisplayName    = $cols[0].Trim()
                        DisplayVersion = $cols[2].Trim()
                        Publisher      = $null
                        Source         = 'winget'
                    }
                }
            }
        }
    } catch { }

    $software = @($classic + $appx + $winget) | Where-Object { $_.DisplayName } |
        Sort-Object DisplayName -Unique

    Write-Status -Symbol 'i' -Text "$($software.Count) application(s) found ($($classic.Count) registry, $($appx.Count) AppX, $($winget.Count) winget)" -Color Cyan
    Add-Finding -Category 'Software' -Name 'Installed Applications' -Status 'Info' `
        -Detail "$($software.Count) applications enumerated across registry/AppX/winget." -Recommendation 'N/A' -Severity 'Info'

    # Flag commonly-outdated / high-risk software families for awareness (config-driven watchlist)
    $watchlist = @($Script:Config.SoftwareWatchlist)
    $flagged = $software | Where-Object {
        $name = $_.DisplayName
        $watchlist | Where-Object { $name -like "*$_*" }
    }
    foreach ($f in $flagged) {
        Add-Finding -Category 'Software' -Name "$($f.DisplayName)" -Status 'Warning' `
            -Detail "Version $($f.DisplayVersion) - historically frequent CVE target." `
            -Recommendation 'Verify this is the latest version and patch/remove if unused.' -Severity 'Low'
        Write-Status -Symbol '!' -Text "$($f.DisplayName) $($f.DisplayVersion) - check for updates" -Color Yellow
    }

    return $software
}

function Get-WingetUpgrades {
    <#
        Asks winget itself which installed packages have a newer version
        available. This is more reliable than trying to infer "outdated"
        from our own CVE/watchlist findings, since winget already knows
        the installed vs. latest version for anything it manages.
    #>
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $null }

    try {
        $raw = & winget upgrade --accept-source-agreements 2>$null
    } catch { return $null }
    if (-not $raw) { return @() }

    $headerLine = $raw | Select-String -Pattern '^Name\s+Id\s+Version' | Select-Object -First 1
    if (-not $headerLine) { return @() }  # "No installed package found matching input criteria" or nothing to upgrade

    # $headerLine.LineNumber is 1-based and points at the header row itself,
    # so that same value is the 0-based index of the first data row.
    $dataLines = $raw[$headerLine.LineNumber..($raw.Count - 1)] | Where-Object {
        $_ -match '\S' -and $_ -notmatch '^-+$' -and $_ -notmatch '\d+ upgrades? available' -and $_ -notmatch '^\d+ package'
    }

    $upgrades = foreach ($line in $dataLines) {
        $cols = ($line -split '\s{2,}') | Where-Object { $_ -ne '' }
        if ($cols.Count -ge 4) {
            [PSCustomObject]@{
                Name             = $cols[0].Trim()
                Id               = $cols[1].Trim()
                CurrentVersion   = $cols[2].Trim()
                AvailableVersion = $cols[3].Trim()
            }
        }
    }
    return $upgrades
}

function Invoke-WingetUpgradeMenu {
    <#
        The only function in this tool that modifies the system - everything
        else is read-only. Requires explicit selection from the person
        running the script; nothing is upgraded automatically or silently,
        and it is never called from Invoke-FullScan.
    #>
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "`n  [!] winget was not found on this system." -ForegroundColor Yellow
        Write-Host "      Install 'App Installer' from the Microsoft Store to enable this feature." -ForegroundColor DarkGray
        return
    }

    Write-Host "`n[*] Checking for available winget upgrades..." -ForegroundColor Cyan
    $upgrades = Get-WingetUpgrades
    if ($null -eq $upgrades) {
        Write-Status -Symbol '!' -Text 'Could not query winget for upgrades' -Color Yellow
        return
    }
    if ($upgrades.Count -eq 0) {
        Write-Status -Symbol 'OK' -Text 'No winget-managed upgrades available' -Color Green
        return
    }

    # Cross-reference against earlier Software/CVE findings so items this
    # audit already flagged stand out from routine version bumps.
    $flaggedNames = $Script:Findings | Where-Object { $_.Category -in @('Software', 'CVE') -and $_.Status -in @('Warning', 'Bad') } |
        ForEach-Object { ($_.Name -split ' - ')[0] }
    foreach ($u in $upgrades) {
        $u | Add-Member -NotePropertyName Flagged -NotePropertyValue ([bool]($flaggedNames | Where-Object { $u.Name -like "*$_*" -or $_ -like "*$($u.Name)*" })) -Force
    }
    $upgrades = $upgrades | Sort-Object @{Expression = { -not $_.Flagged }}, Name

    Show-Line
    Write-Host "  Outdated software detected via winget:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $upgrades.Count; $i++) {
        $u = $upgrades[$i]
        $tag = if ($u.Flagged) { ' [flagged earlier in this audit]' } else { '' }
        $color = if ($u.Flagged) { 'Yellow' } else { 'White' }
        Write-Host ("  [{0,2}] " -f ($i + 1)) -NoNewline
        Write-Host ("{0,-28} {1,-14} -> {2}{3}" -f $u.Name, $u.CurrentVersion, $u.AvailableVersion, $tag) -ForegroundColor $color
    }
    Show-Line
    Write-Host "  This runs 'winget upgrade' and WILL MODIFY installed software on this machine." -ForegroundColor Yellow
    Write-Host "  Enter numbers to upgrade (e.g. 1,3,5), 'all', or press Enter to skip: " -NoNewline -ForegroundColor Cyan
    $selection = (Read-Host).Trim()

    if (-not $selection) {
        Write-Host "  Skipped - no changes made." -ForegroundColor DarkGray
        return
    }

    if ($selection.ToLower() -eq 'all') {
        $targets = $upgrades
    } else {
        $indices = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 }
        $targets = $indices | Where-Object { $_ -ge 0 -and $_ -lt $upgrades.Count } | ForEach-Object { $upgrades[$_] }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Host "  No valid selections - no changes made." -ForegroundColor Yellow
        return
    }

    foreach ($t in $targets) {
        Write-Host "`n  Upgrading $($t.Name) ($($t.CurrentVersion) -> $($t.AvailableVersion))..." -ForegroundColor Cyan
        try {
            & winget upgrade --id $t.Id --silent --accept-package-agreements --accept-source-agreements | Out-Host
            $exitCode = $LASTEXITCODE
            if ($exitCode -eq 0) {
                Write-Status -Symbol 'OK' -Text "$($t.Name) upgraded successfully" -Color Green
                Add-Finding -Category 'Remediation' -Name "Upgraded: $($t.Name)" -Status 'Good' `
                    -Detail "$($t.CurrentVersion) -> $($t.AvailableVersion) via winget (id: $($t.Id))." `
                    -Recommendation 'N/A' -Severity 'Info'
            } else {
                Write-Status -Symbol '!' -Text "$($t.Name) upgrade returned exit code $exitCode - check manually" -Color Yellow
                Add-Finding -Category 'Remediation' -Name "Upgrade Attempted: $($t.Name)" -Status 'Warning' `
                    -Detail "winget exited with code $exitCode for id $($t.Id)." `
                    -Recommendation 'Run "winget upgrade --id $($t.Id)" manually and review the output.' -Severity 'Low'
            }
        } catch {
            Write-Status -Symbol 'X' -Text "$($t.Name) upgrade failed: $_" -Color Red
            Add-Finding -Category 'Remediation' -Name "Upgrade Failed: $($t.Name)" -Status 'Bad' `
                -Detail "$_" -Recommendation "Run `"winget upgrade --id $($t.Id)`" manually and review the output." -Severity 'Low'
        }
    }
}

function Get-NvdHeaders {
    if ($Script:Config.NvdApiKey) { return @{ 'apiKey' = $Script:Config.NvdApiKey } }
    return @{}
}

function Resolve-CpeName {
    <#
        Looks up the CPE dictionary for a product name and returns the best
        vendor:product match, e.g. "google:chrome". This is what lets us
        query NVD with a fully-versioned CPE string instead of a fuzzy
        keyword, so version-range matching happens server-side against
        real affected-version data rather than a text match on the CVE
        description.
    #>
    param([string]$ProductName, [hashtable]$Headers, [int]$DelayMs)

    $uri = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=$([uri]::EscapeDataString($ProductName))&resultsPerPage=5"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Headers -TimeoutSec 15
        Start-Sleep -Milliseconds $DelayMs
        $cpeUri = $resp.products | Select-Object -First 1 -ExpandProperty cpe -ErrorAction SilentlyContinue
        if ($cpeUri -and $cpeUri.cpeName) {
            $parts = $cpeUri.cpeName -split ':'
            if ($parts.Count -ge 6) {
                return [PSCustomObject]@{ Vendor = $parts[3]; Product = $parts[4] }
            }
        }
    } catch { }
    return $null
}

function Get-CveForVersionedCpe {
    param([string]$CpeName, [hashtable]$Headers, [int]$DelayMs)

    $uri = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$([uri]::EscapeDataString($CpeName))&resultsPerPage=5"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Headers -TimeoutSec 15
        Start-Sleep -Milliseconds $DelayMs
        return $resp.vulnerabilities
    } catch {
        return $null
    }
}

function Get-CveFindingsForSoftware {
    <#
        Pure function: given one software item, returns an array of finding
        hashtables (no console output, no shared state) so it can run
        equally well sequentially or inside a parallel runspace.
    #>
    param($Item, [hashtable]$Headers, [int]$DelayMs)

    $results = @()
    $cpe = Resolve-CpeName -ProductName $Item.DisplayName -Headers $Headers -DelayMs $DelayMs

    $vulns = $null
    $matchedVia = $null
    if ($cpe) {
        $versionedCpe = "cpe:2.3:a:$($cpe.Vendor):$($cpe.Product):$($Item.DisplayVersion):*:*:*:*:*:*:*"
        $vulns = Get-CveForVersionedCpe -CpeName $versionedCpe -Headers $Headers -DelayMs $DelayMs
        $matchedVia = 'cpe'
    }

    # Fall back to a (clearly labeled, lower-confidence) keyword search only
    # if CPE resolution failed outright - e.g. product not in the CPE dictionary.
    if (-not $cpe) {
        $query = "$($Item.DisplayName) $($Item.DisplayVersion)"
        $uri = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$([uri]::EscapeDataString($query))&resultsPerPage=3"
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Headers -TimeoutSec 15
            Start-Sleep -Milliseconds $DelayMs
            $vulns = $resp.vulnerabilities
            $matchedVia = 'keyword'
        } catch { }
    }

    if ($vulns -and $vulns.Count -gt 0) {
        foreach ($v in $vulns) {
            $cveId = $v.cve.id
            $desc = ($v.cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
            $metrics = $v.cve.metrics
            $cvss = $null
            if ($metrics.cvssMetricV31) { $cvss = $metrics.cvssMetricV31[0].cvssData.baseScore }
            elseif ($metrics.cvssMetricV30) { $cvss = $metrics.cvssMetricV30[0].cvssData.baseScore }
            elseif ($metrics.cvssMetricV2) { $cvss = $metrics.cvssMetricV2[0].cvssData.baseScore }

            $sev = 'Low'
            if ($cvss -ge 9) { $sev = 'Critical' } elseif ($cvss -ge 7) { $sev = 'High' } elseif ($cvss -ge 4) { $sev = 'Medium' }

            $confidence = if ($matchedVia -eq 'cpe') { 'CPE version-matched' } else { 'keyword match - low confidence' }
            $results += @{
                Name           = "$($Item.DisplayName) $($Item.DisplayVersion) - $cveId"
                Detail         = "$desc (CVSS: $cvss, $confidence)"
                Recommendation = 'Verify applicability against the vendor advisory and patch to the latest version.'
                Severity       = $sev
                MatchedVia     = $matchedVia
            }
        }
    } else {
        $results += @{
            Name           = "$($Item.DisplayName) $($Item.DisplayVersion)"
            Detail         = "No CVEs matched via $(if ($matchedVia) { $matchedVia } else { 'lookup' })."
            Recommendation = 'N/A'
            Severity       = 'Info'
            MatchedVia     = $matchedVia
            NoMatch        = $true
        }
    }
    return $results
}

function Invoke-CveLookup {
    param([Parameter(Mandatory)][array]$Software)

    Write-Host "`n[*] Cross-referencing software against NVD (informational)..." -ForegroundColor Cyan
    Write-Host "    Uses CPE-based version matching where possible (falls back to a" -ForegroundColor DarkGray
    Write-Host "    labeled keyword search only if a product has no CPE dictionary entry)." -ForegroundColor DarkGray

    $pattern = $Script:Config.CveWatchlistPattern
    $maxTargets = [int]$Script:Config.MaxCveTargets
    $targets = $Software | Where-Object { $_.DisplayName -match $pattern } | Select-Object -First $maxTargets

    if (-not $targets) {
        Write-Status -Symbol 'i' -Text 'No high-signal software matched for CVE lookup' -Color DarkGray
        return
    }

    $headers = Get-NvdHeaders
    $delayMs = [int]$Script:Config.NvdDelayMs

    # These lookups are network-latency bound (NVD round-trips + a polite
    # delay per call), which is exactly the case where concurrency actually
    # pays off - unlike the local registry/CIM checks elsewhere in this
    # script, which finish in milliseconds and would only pick up thread
    # overhead from parallelizing. PS7+ runs the per-item lookups
    # concurrently; PowerShell 5.1 falls back to sequential.
    #
    # Note: the parallel branch defines its helper functions literally,
    # inline, inside the -Parallel block below - it does NOT reconstruct
    # function bodies from strings or Invoke-Expression/dynamically build
    # scriptblocks at runtime. Each -Parallel scriptblock runs in its own
    # runspace with nothing carried over from the parent scope except what's
    # explicitly passed via $using:, so the straightforward, supported fix
    # is just to write the functions directly where they're used.
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $allResults = $targets | ForEach-Object -ThrottleLimit 5 -Parallel {
            $item = $_
            $headers = $using:headers
            $delayMs = $using:delayMs

            function Resolve-CpeName {
                param([string]$ProductName, [hashtable]$Headers, [int]$DelayMs)
                $uri = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=$([uri]::EscapeDataString($ProductName))&resultsPerPage=5"
                try {
                    $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Headers -TimeoutSec 15
                    Start-Sleep -Milliseconds $DelayMs
                    $cpeUri = $resp.products | Select-Object -First 1 -ExpandProperty cpe -ErrorAction SilentlyContinue
                    if ($cpeUri -and $cpeUri.cpeName) {
                        $parts = $cpeUri.cpeName -split ':'
                        if ($parts.Count -ge 6) { return [PSCustomObject]@{ Vendor = $parts[3]; Product = $parts[4] } }
                    }
                } catch { }
                return $null
            }

            function Get-CveForVersionedCpe {
                param([string]$CpeName, [hashtable]$Headers, [int]$DelayMs)
                $uri = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$([uri]::EscapeDataString($CpeName))&resultsPerPage=5"
                try {
                    $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $Headers -TimeoutSec 15
                    Start-Sleep -Milliseconds $DelayMs
                    return $resp.vulnerabilities
                } catch { return $null }
            }

            $cpe = Resolve-CpeName -ProductName $item.DisplayName -Headers $headers -DelayMs $delayMs
            $vulns = $null
            $matchedVia = $null
            if ($cpe) {
                $versionedCpe = "cpe:2.3:a:$($cpe.Vendor):$($cpe.Product):$($item.DisplayVersion):*:*:*:*:*:*:*"
                $vulns = Get-CveForVersionedCpe -CpeName $versionedCpe -Headers $headers -DelayMs $delayMs
                $matchedVia = 'cpe'
            } else {
                $query = "$($item.DisplayName) $($item.DisplayVersion)"
                $uri = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$([uri]::EscapeDataString($query))&resultsPerPage=3"
                try {
                    $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 15
                    Start-Sleep -Milliseconds $delayMs
                    $vulns = $resp.vulnerabilities
                    $matchedVia = 'keyword'
                } catch { }
            }

            $results = @()
            if ($vulns -and $vulns.Count -gt 0) {
                foreach ($v in $vulns) {
                    $cveId = $v.cve.id
                    $desc = ($v.cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
                    $metrics = $v.cve.metrics
                    $cvss = $null
                    if ($metrics.cvssMetricV31) { $cvss = $metrics.cvssMetricV31[0].cvssData.baseScore }
                    elseif ($metrics.cvssMetricV30) { $cvss = $metrics.cvssMetricV30[0].cvssData.baseScore }
                    elseif ($metrics.cvssMetricV2) { $cvss = $metrics.cvssMetricV2[0].cvssData.baseScore }
                    $sev = 'Low'
                    if ($cvss -ge 9) { $sev = 'Critical' } elseif ($cvss -ge 7) { $sev = 'High' } elseif ($cvss -ge 4) { $sev = 'Medium' }
                    $confidence = if ($matchedVia -eq 'cpe') { 'CPE version-matched' } else { 'keyword match - low confidence' }
                    $results += @{
                        Name           = "$($item.DisplayName) $($item.DisplayVersion) - $cveId"
                        Detail         = "$desc (CVSS: $cvss, $confidence)"
                        Recommendation = 'Verify applicability against the vendor advisory and patch to the latest version.'
                        Severity       = $sev
                        MatchedVia     = $matchedVia
                    }
                }
            } else {
                $results += @{
                    Name           = "$($item.DisplayName) $($item.DisplayVersion)"
                    Detail         = "No CVEs matched via $(if ($matchedVia) { $matchedVia } else { 'lookup' })."
                    Recommendation = 'N/A'
                    Severity       = 'Info'
                    MatchedVia     = $matchedVia
                    NoMatch        = $true
                }
            }
            $results
        }
    } else {
        $allResults = foreach ($t in $targets) {
            Get-CveFindingsForSoftware -Item $t -Headers $headers -DelayMs $delayMs
        }
    }

    foreach ($r in $allResults) {
        if ($r.NoMatch) {
            Write-Status -Symbol 'OK' -Text "$($r.Name): $($r.Detail)" -Color Green
            continue
        }
        Add-Finding -Category 'CVE' -Name $r.Name -Status 'Warning' `
            -Detail $r.Detail -Recommendation $r.Recommendation -Severity $r.Severity
        Write-Status -Symbol '!' -Text "$($r.Name) [$($r.MatchedVia)]" -Color Yellow
    }

    Write-Host "`n    Note: even CPE-matched results are best-effort against public NVD data." -ForegroundColor DarkGray
    Write-Host "    Always verify against vendor advisories before treating a match as confirmed." -ForegroundColor DarkGray
}

# endregion

# ---------------------------------------------------------------------------
# region: Reporting
# ---------------------------------------------------------------------------

function Show-Summary {
    $score = Get-RiskScore
    $level = Get-RiskLevel -Score $score
    $levelColor = switch ($level) {
        'LOW'      { 'Green' }
        'MEDIUM'   { 'Yellow' }
        'HIGH'     { 'Red' }
        'CRITICAL' { 'Red' }
    }

    Show-Line
    Write-Host "  AUDIT SUMMARY" -ForegroundColor Cyan
    Show-Line
    $bad = ($Script:Findings | Where-Object Status -eq 'Bad').Count
    $warn = ($Script:Findings | Where-Object Status -eq 'Warning').Count
    $good = ($Script:Findings | Where-Object Status -eq 'Good').Count

    Write-Host "  Findings: " -NoNewline
    Write-Host "$bad Bad " -ForegroundColor Red -NoNewline
    Write-Host "| $warn Warning " -ForegroundColor Yellow -NoNewline
    Write-Host "| $good Good" -ForegroundColor Green

    $barLength = 20
    $filled = [math]::Round(($score / 100) * $barLength)
    $bar = ('#' * $filled).PadRight($barLength, '.')
    Write-Host "`n  Risk Score : [$bar] $score / 100" -ForegroundColor $levelColor
    Write-Host "  Risk Level : $level" -ForegroundColor $levelColor
    Show-Line
}

function Export-HtmlReport {
    param([array]$Software)

    $score = Get-RiskScore
    $level = Get-RiskLevel -Score $score
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $path = Join-Path $Script:ReportDir "Perseus_AuditReport_$timestamp.html"

    function Get-StatusColor($status) {
        switch ($status) {
            'Bad'     { return '#e74c3c' }
            'Warning' { return '#f39c12' }
            'Good'    { return '#2ecc71' }
            default   { return '#7f8c8d' }
        }
    }

    $rows = ($Script:Findings | Sort-Object @{Expression={Get-SeverityWeight $_.Severity}; Descending=$true} | ForEach-Object {
        $c = Get-StatusColor $_.Status
        "<tr><td>$($_.Category)</td><td>$($_.Name)</td><td style='color:$c;font-weight:bold'>$($_.Status)</td><td>$($_.Severity)</td><td>$($_.Detail)</td><td>$($_.Recommendation)</td></tr>"
    }) -join "`n"

    $softwareRows = ($Software | ForEach-Object {
        "<tr><td>$($_.DisplayName)</td><td>$($_.DisplayVersion)</td><td>$($_.Publisher)</td></tr>"
    }) -join "`n"

    $levelColor = switch ($level) {
        'LOW' { '#2ecc71' } 'MEDIUM' { '#f39c12' } 'HIGH' { '#e67e22' } default { '#e74c3c' }
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Project Perseus - Security Audit Report - $env:COMPUTERNAME</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#1e1e2f; color:#e0e0e0; margin:0; padding:2rem; }
  h1 { color:#00d4ff; }
  .summary { display:flex; gap:2rem; margin-bottom:2rem; }
  .card { background:#2a2a3d; padding:1.5rem; border-radius:10px; flex:1; text-align:center; }
  .score { font-size:3rem; font-weight:bold; color:$levelColor; }
  table { width:100%; border-collapse:collapse; margin-bottom:2rem; }
  th, td { padding:8px 12px; border-bottom:1px solid #3a3a4d; text-align:left; font-size:0.9rem; }
  th { background:#2a2a3d; color:#00d4ff; }
  tr:hover { background:#2f2f45; }
  .meta { color:#999; font-size:0.85rem; margin-bottom:1.5rem;}
</style>
</head>
<body>
  <h1>Project Perseus</h1>
  <div style="color:#00d4ff;font-size:0.95rem;margin-top:-0.5rem;margin-bottom:1rem;">PowerShell Endpoint Review and Security Evaluation Utility Suite</div>
  <div class='meta'>Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $env:USERNAME &nbsp;|&nbsp; Generated: $(Get-Date)</div>

  <div class='summary'>
    <div class='card'><div class='score'>$score</div>Risk Score / 100</div>
    <div class='card'><div class='score' style='color:$levelColor'>$level</div>Risk Level</div>
    <div class='card'><div class='score' style='color:#e74c3c'>$(($Script:Findings | Where-Object Status -eq 'Bad').Count)</div>Bad Findings</div>
    <div class='card'><div class='score' style='color:#f39c12'>$(($Script:Findings | Where-Object Status -eq 'Warning').Count)</div>Warnings</div>
  </div>

  <h2>Findings</h2>
  <table>
    <tr><th>Category</th><th>Name</th><th>Status</th><th>Severity</th><th>Detail</th><th>Recommendation</th></tr>
    $rows
  </table>

  <h2>Installed Software ($($Software.Count))</h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Publisher</th></tr>
    $softwareRows
  </table>

</body>
</html>
"@

    $html | Out-File -FilePath $path -Encoding UTF8
    Write-Host "`n  [OK] Report saved to: $path" -ForegroundColor Green
    return $path
}

function Export-JsonReport {
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $path = Join-Path $Script:ReportDir "Perseus_AuditReport_$timestamp.json"
    $obj = [PSCustomObject]@{
        Host      = $env:COMPUTERNAME
        Generated = Get-Date
        Score     = Get-RiskScore
        Level     = Get-RiskLevel -Score (Get-RiskScore)
        Findings  = $Script:Findings
    }
    $obj | ConvertTo-Json -Depth 6 | Out-File -FilePath $path -Encoding UTF8
    Write-Host "  [OK] JSON report saved to: $path" -ForegroundColor Green
    return $path
}

function Export-CsvReport {
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $path = Join-Path $Script:ReportDir "Perseus_AuditReport_$timestamp.csv"
    $Script:Findings | Select-Object Category, Name, Status, Severity, InternetExposed, Detail, Recommendation, Timestamp |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host "  [OK] CSV report saved to: $path" -ForegroundColor Green
    return $path
}

# endregion

# ---------------------------------------------------------------------------
# region: Menu
# ---------------------------------------------------------------------------

function Invoke-FullScan {
    $Script:Findings.Clear()
    Invoke-WindowsUpdateCheck
    Invoke-LocalAdminCheck
    Invoke-DefenderCheck
    Invoke-FirewallCheck
    Invoke-RdpCheck
    Invoke-SmbCheck
    Invoke-PowerShellLoggingCheck
    Invoke-UacCheck
    Invoke-BitLockerCheck
    Invoke-ModernSecurityCheck
    Invoke-NetworkPortCheck
    Invoke-PersistenceCheck
    $Script:LastSoftware = Invoke-SoftwareInventory
    Show-Summary
}

function Show-Menu {
    Show-Banner
    Write-Host "  [1]  Missing Security Updates"
    Write-Host "  [2]  Local Administrator Accounts"
    Write-Host "  [3]  Windows Defender Health"
    Write-Host "  [4]  Firewall Audit"
    Write-Host "  [5]  RDP Configuration"
    Write-Host "  [6]  SMB Configuration"
    Write-Host "  [7]  PowerShell Logging / Execution Policy"
    Write-Host "  [8]  UAC Configuration"
    Write-Host "  [9]  BitLocker Status"
    Write-Host "  [10] Modern Security (Secure Boot / VBS / Cred Guard / HVCI / LSA / WDigest / ASR / LAPS)"
    Write-Host "  [11] Open/Listening Ports (with process & service attribution)"
    Write-Host "  [12] Persistence Check (Run keys, Startup, Scheduled Tasks, Unquoted Paths)"
    Write-Host "  [13] Installed Software Inventory (registry + AppX + winget)"
    Write-Host "  [14] CVE Lookup - CPE version-matched (requires internet, run 13 first)"
    Write-Host "  [15] FULL SCAN (all read-only checks above)"
    Write-Host "  [16] Export HTML Report"
    Write-Host "  [17] Export JSON Report"
    Write-Host "  [18] Export CSV Report"
    Write-Host "  [19] Show Last Summary"
    Write-Host "  [20] Upgrade Outdated Software via winget " -NoNewline
    Write-Host "(modifies your system)" -ForegroundColor Yellow
    Write-Host "  [0]  Exit"
    Show-Line
    Write-Host "  Selection: " -NoNewline -ForegroundColor Cyan
}

# endregion

# ---------------------------------------------------------------------------
# region: Main loop
# ---------------------------------------------------------------------------

$Script:LastSoftware = @()

do {
    Show-Menu
    $choice = Read-Host
    switch ($choice) {
        '1'  { Invoke-WindowsUpdateCheck }
        '2'  { Invoke-LocalAdminCheck }
        '3'  { Invoke-DefenderCheck }
        '4'  { Invoke-FirewallCheck }
        '5'  { Invoke-RdpCheck }
        '6'  { Invoke-SmbCheck }
        '7'  { Invoke-PowerShellLoggingCheck }
        '8'  { Invoke-UacCheck }
        '9'  { Invoke-BitLockerCheck }
        '10' { Invoke-ModernSecurityCheck }
        '11' { Invoke-NetworkPortCheck | Out-Null }
        '12' { Invoke-PersistenceCheck }
        '13' { $Script:LastSoftware = Invoke-SoftwareInventory }
        '14' {
            if (-not $Script:LastSoftware -or $Script:LastSoftware.Count -eq 0) {
                Write-Host "`n  [!] Run option 13 first to build the software inventory." -ForegroundColor Yellow
            } else {
                Invoke-CveLookup -Software $Script:LastSoftware
            }
        }
        '15' { Invoke-FullScan }
        '16' { Export-HtmlReport -Software $Script:LastSoftware | Out-Null }
        '17' { Export-JsonReport | Out-Null }
        '18' { Export-CsvReport | Out-Null }
        '19' { Show-Summary }
        '20' { Invoke-WingetUpgradeMenu }
        '0'  { Write-Host "`n  Goodbye." -ForegroundColor Cyan }
        default { Write-Host "`n  Invalid selection." -ForegroundColor Red }
    }
    if ($choice -ne '0') {
        Write-Host "`n  Press Enter to return to the menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
} while ($choice -ne '0')

if ($Transcript) { try { Stop-Transcript | Out-Null } catch { } }

# endregion
