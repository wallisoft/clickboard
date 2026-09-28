; Clickboard Windows installer (built by the GitHub release workflow).
; Version comes from the git tag: ISCC /DAppVersion=2.5.1 clickboard.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6E0C4F2A-9B7D-4C1E-8A53-2F4D9C7B1E60}
AppName=Clickboard
AppVersion={#AppVersion}
AppVerName=Clickboard {#AppVersion}
AppPublisher=Wallisoft
AppPublisherURL=https://clickboard.eur.bz
AppSupportURL=https://github.com/wallisoft/clickboard
DefaultDirName={autopf}\Clickboard
DefaultGroupName=Clickboard
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=Output
OutputBaseFilename=Clickboard-Setup
SetupIconFile=clickboard.ico
UninstallDisplayIcon={app}\Clickboard.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Admin is needed once, to add the firewall rules below.
PrivilegesRequired=admin
CloseApplications=yes

[Tasks]
Name: "startup"; Description: "Start Clickboard when I sign in"; GroupDescription: "Options:"

[Files]
Source: "..\dist\Clickboard.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\Clickboard"; Filename: "{app}\Clickboard.exe"
Name: "{group}\Clickboard settings"; Filename: "{app}\Clickboard.exe"; Parameters: "--settings"
Name: "{userstartup}\Clickboard"; Filename: "{app}\Clickboard.exe"; Tasks: startup

[Run]
; Let your machines reach each other on private networks only.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Clickboard (TCP 47800)"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Clickboard local discovery (UDP 47802)"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Clickboard (TCP 47800)"" dir=in action=allow protocol=TCP localport=47800 profile=private,domain"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Clickboard local discovery (UDP 47802)"" dir=in action=allow protocol=UDP localport=47802 profile=private,domain"; Flags: runhidden
Filename: "{app}\Clickboard.exe"; Description: "Start Clickboard now"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\Clickboard.exe"; Parameters: "--quit"; Flags: runhidden; RunOnceId: "QuitClickboard"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Clickboard (TCP 47800)"""; Flags: runhidden; RunOnceId: "DelTcpRule"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Clickboard local discovery (UDP 47802)"""; Flags: runhidden; RunOnceId: "DelUdpRule"
