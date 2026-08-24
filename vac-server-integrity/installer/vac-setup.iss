; VAC Anti-Cheat Windows Client Installer
; Requires Inno Setup 6+ (https://jrsoftware.org/isinfo.php)
; Build: iscc vac-setup.iss
;
; Zero-typing flow: the plugin's magic link serves vac-setup.zip containing
; this installer next to a vac-preload.ini with server+token baked in.
; When extracted together and launched, all pages come prefilled - just click
; through. Manual flow still works: user enters server address + access code
; shown in game chat.

#define MyAppName "VAC Anti-Cheat Client"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "VAC Team"
#define MyAppURL "https://github.com/text70/VAC"

[Setup]
AppId={{B6F3A2C1-7D4E-4F2A-9B1E-8C5D3A6F2E1D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={pf64}\Vac
DefaultGroupName=VAC
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=vac-setup
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\vac-daemon-win.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "Source\vac.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "Source\vac-daemon-win.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\vac-daemon-win.exe"; Parameters: "--doctor"; \
    Description: "Run VAC client diagnostics"; \
    Flags: postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop VacDaemon"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete VacDaemon"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "stop Vac"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete Vac"; Flags: runhidden

[Code]

var
  ServerPage: TInputQueryWizardPage;
  TokenPage: TInputQueryWizardPage;
  ModePage: TInputOptionWizardPage;
  PreloadServer: string;
  PreloadToken: string;

function IniValue(const Text: string; const Key: string): string;
var
  LineStart, LineEnd, Eq: Integer;
  Line, K: string;
begin
  Result := '';
  LineStart := 1;
  while LineStart <= Length(Text) do
  begin
    LineEnd := Pos(#13#10, Copy(Text, LineStart, MaxInt));
    if LineEnd = 0 then
      LineEnd := Length(Text) + 1
    else
      LineEnd := LineStart + LineEnd - 1;
    Line := Trim(Copy(Text, LineStart, LineEnd - LineStart));
    if (Line <> '') and (Copy(Line, 1, 1) <> '#') and (Copy(Line, 1, 1) <> ';') then
    begin
      Eq := Pos('=', Line);
      if Eq > 0 then
      begin
        K := Lowercase(Trim(Copy(Line, 1, Eq - 1)));
        if K = Key then
        begin
          Result := Trim(Copy(Line, Eq + 1, MaxInt));
          Exit;
        end;
      end;
    end;
    LineStart := LineEnd + 2;
  end;
end;

function InitializeSetup(): Boolean;
var
  PreloadPath, Text, Raw: string;
begin
  Result := True;
  PreloadServer := '';
  PreloadToken := '';
  // Magic-link flow: vac-preload.ini sits next to the installer in the ZIP.
  PreloadPath := ExtractFilePath(ParamStr(0)) + 'vac-preload.ini';
  if FileExists(PreloadPath) then
  begin
    if LoadStringFromFile(PreloadPath, Raw) then
    begin
      Text := Raw;
      StringChangeEx(Text, #10, '', True);
      PreloadServer := IniValue(Text, 'server');
      PreloadToken := IniValue(Text, 'token');
    end;
  end;
end;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(
    wpSelectDir,
    'Server Configuration',
    'Which VAC-enabled game server is this client for?',
    'Enter the IP:port of your server (e.g., 192.168.1.100:28084). ' +
    'Pre-filled automatically when using the download link from game chat.');
  ServerPage.Add('Server address:', False);
  ServerPage.Values[0] := PreloadServer;

  TokenPage := CreateInputQueryPage(
    ServerPage.ID,
    'Access Code',
    'Paste your personal access code',
    'Copy the access code shown in the server chat message. ' +
    'Pre-filled automatically when using the download link from game chat.');
  TokenPage.Add('Access code:', False);
  TokenPage.Values[0] := PreloadToken;

  ModePage := CreateInputOptionPage(
    TokenPage.ID,
    'Protection Level',
    'Choose your protection level',
    'Full protection uses a kernel driver for stronger anti-cheat coverage. ' +
    'If the driver cannot load on your system, Basic protection still works.',
    True);
  ModePage.Add('Full protection (recommended)');
  ModePage.Add('Basic protection (user-mode only)');
  ModePage.SelectedValueIndex := 0;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    if Trim(ServerPage.Values[0]) = '' then
    begin
      MsgBox('Please enter a server address.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function PrepareConfig(const Server: string; const Token: string): string;
begin
  Result := '# VAC daemon config (auto-generated by installer)' + #13#10 +
            'server=' + Server + #13#10 +
            'token=' + Token + #13#10 +
            '; Optional: override automatic Steam ID discovery' + #13#10 +
            '; steam_id=76561198000000000' + #13#10;
end;

procedure InstallDriverAndDaemon;
var
  ResultCode: Integer;
  DriverBin: string;
begin
  if ModePage.SelectedValueIndex = 0 then
  begin
    Log('Installing VAC kernel driver...');
    DriverBin := ExpandConstant('{app}') + '\vac.sys';
    Exec(ExpandConstant('{sys}\sc.exe'),
      'create Vac type= kernel binPath= "' + DriverBin + '" start= auto',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'),
      'start Vac', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode <> 0 then
      MsgBox('The kernel driver could not be started (this is normal on systems ' +
        'that block unsigned drivers). The client will continue with Basic ' +
        'protection automatically.', mbInformation, MB_OK);
  end;

  Log('Installing VAC daemon service...');
  Exec(ExpandConstant('{sys}\sc.exe'),
    'create VacDaemon binPath= "' + ExpandConstant('{app}') + '\vac-daemon-win.exe" start= auto displayname= "VAC Daemon"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StartDaemonService;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'),
    'start VacDaemon', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: string;
  ServerIP, AccessToken: string;
begin
  if CurStep = ssPostInstall then
  begin
    ServerIP := Trim(ServerPage.Values[0]);
    AccessToken := Trim(TokenPage.Values[0]);

    ConfigPath := ExpandConstant('{app}\vac-daemon.ini');
    SaveStringToFile(ConfigPath, PrepareConfig(ServerIP, AccessToken), False);

    InstallDriverAndDaemon;
    StartDaemonService;
  end;
end;
