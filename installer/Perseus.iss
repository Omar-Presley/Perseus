; Inno Setup script for Perseus.
; Build the publish output first, then compile this script:
;   dotnet publish -c Release -p:PublishProfile=win-x64
;   iscc installer\Perseus.iss
;
; Keep AppId stable across releases - it's how Windows/Inno Setup recognizes
; upgrades vs a fresh install of a different app.
#define MyAppName "Perseus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Perseus"
#define MyAppExeName "Perseus.exe"
#define PublishDir "..\bin\Release\net10.0\win-x64\publish"

[Setup]
AppId={{FDAAFC2E-8334-4C6C-A103-0CFA88ACC9CE}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Per-user install under %LocalAppData% - no admin/UAC prompt required, and the
; app's own config/report folders (written next to the exe) stay user-writable,
; unlike an install under Program Files.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=PerseusSetup
SetupIconFile=..\Assets\PerseusIcon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Everything from the self-contained single-file publish output except debug
; symbols (*.pdb) - those aren't needed to run the app.
Source: "{#PublishDir}\*"; DestDir: "{app}"; Excludes: "*.pdb"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
