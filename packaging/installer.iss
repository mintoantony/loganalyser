; Windows installer for LogAnalyser (Inno Setup 6.1 or later). Built by packaging/build_windows.ps1.
;
; A normal setup wizard for people with no technical background:
;   Welcome -> Checking your computer -> (folder, first install only) -> Ready -> Installing -> Finish
; The check page shows a tick or a cross for each requirement. The only thing the app may need that
; Windows does not always have is the Microsoft WebView2 Runtime (it draws the app's window); if it is
; missing, Setup downloads and installs it with a progress bar. Without it the app still works, in the
; web browser. To try that path on a PC that has WebView2, run the installer with /WEBVIEW2=missing.
#define AppName "LogAnalyser"
#define AppVersion "1.1.0"
#define AppExe "LogAnalyser.exe"
; The app folder is about 50 MB; ask for some room to spare.
#define NeededMB 150
#define WebView2Url "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
#define WebView2Guid "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

[Setup]
AppId={{6C1B7E8A-3D52-4E1F-9B0B-2F5D8A4C9E71}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=LogAnalyser
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=LogAnalyser-{#AppVersion}-Windows-Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
WizardImageFile=wizard-sidebar-100.bmp,wizard-sidebar-125.bmp,wizard-sidebar-150.bmp,wizard-sidebar-200.bmp
WizardSmallImageFile=wizard-small-100.bmp,wizard-small-125.bmp,wizard-small-150.bmp,wizard-small-200.bmp
Compression=lzma2
SolidCompression=yes
CloseApplications=yes

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nLogAnalyser reads log files and tells you the most likely reason something failed, with the lines that prove it.%n%nSetup will first check that your computer is ready.
FinishedHeadingLabel=LogAnalyser is ready
FinishedLabelNoIcons=LogAnalyser is installed.%n%nTo find out why something broke, open LogAnalyser and drop a folder of log files onto its window.
FinishedLabel=LogAnalyser is installed. You can open it from the Start menu.%n%nTo find out why something broke, drop a folder of log files onto its window.

[Tasks]
Name: "desktopicon"; Description: "Put a LogAnalyser shortcut on the desktop"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\LogAnalyser\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Open LogAnalyser now"; Flags: nowait postinstall skipifsilent

[Code]
const
  ColorGood = $000CA30C;    { green  #0ca30c }
  ColorBad = $003B3BD0;     { red    #d03b3b }
  ColorAction = $000078B0;  { amber  #b07800 }
  GlyphGood = #$2714;       { heavy check mark }
  GlyphBad = #$2716;        { heavy multiplication x }
  GlyphAction = #$25CF;     { black circle: Setup will do it }
  GlyphInfo = #$25CB;       { white circle: optional }

var
  CheckPage: TWizardPage;
  SummaryLabel: TNewStaticText;
  RowTop: Integer;
  NeedWebView2: Boolean;
  WebView2Done: Boolean;
  EnoughSpace: Boolean;
  DownloadPage: TDownloadWizardPage;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

{ The WebView2 Runtime registers its version under EdgeUpdate, per machine or per user. }
function WebView2Installed(var Version: String): Boolean;
var
  Key: String;
begin
  Key := 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{#WebView2Guid}';
  Result := False;
  if not RegQueryStringValue(HKLM32, Key, 'pv', Version) then
    if not RegQueryStringValue(HKLM64, Key, 'pv', Version) then
      if not RegQueryStringValue(HKCU, Key, 'pv', Version) then
        Version := '';
  Result := (Version <> '') and (Version <> '0.0.0.0');
  if ExpandConstant('{param:WEBVIEW2|auto}') = 'missing' then
    Result := False;
end;

function SizeText(MB: Int64): String;
begin
  if MB >= 10240 then
    Result := IntToStr(MB div 1024) + ' GB'
  else
    Result := IntToStr(MB) + ' MB';
end;

{ One line on the check page: a coloured mark, a title and a grey explanation under it. }
procedure AddRow(Glyph: String; Color: TColor; Title, Detail: String);
var
  Mark, Head, Body: TNewStaticText;
begin
  Mark := TNewStaticText.Create(CheckPage);
  Mark.Parent := CheckPage.Surface;
  Mark.Caption := Glyph;
  Mark.Font.Name := 'Segoe UI Symbol';
  Mark.Font.Size := 13;
  Mark.Font.Color := Color;
  Mark.Left := 0;
  Mark.Top := RowTop - ScaleY(3);

  Head := TNewStaticText.Create(CheckPage);
  Head.Parent := CheckPage.Surface;
  Head.Caption := Title;
  Head.Font.Style := [fsBold];
  Head.Left := ScaleX(28);
  Head.Top := RowTop;

  Body := TNewStaticText.Create(CheckPage);
  Body.Parent := CheckPage.Surface;
  Body.AutoSize := False;
  Body.WordWrap := True;
  Body.Caption := Detail;
  Body.Font.Color := clGrayText;
  Body.Left := ScaleX(28);
  Body.Top := RowTop + ScaleY(17);
  Body.Width := CheckPage.SurfaceWidth - ScaleX(28);
  Body.Height := ScaleY(30);

  RowTop := RowTop + ScaleY(60);
end;

procedure BuildCheckPage;
var
  Version: TWindowsVersion;
  WebViewVersion, Drive: String;
  FreeBytes, TotalBytes: Int64;
  FreeMB: Int64;
begin
  CheckPage := CreateCustomPage(wpWelcome, 'Checking your computer',
    'Setup checks that LogAnalyser can run on this computer.');

  SummaryLabel := TNewStaticText.Create(CheckPage);
  SummaryLabel.Parent := CheckPage.Surface;
  SummaryLabel.AutoSize := False;
  SummaryLabel.WordWrap := True;
  SummaryLabel.Width := CheckPage.SurfaceWidth;
  SummaryLabel.Height := ScaleY(34);
  SummaryLabel.Font.Style := [fsBold];
  SummaryLabel.Top := 0;
  RowTop := ScaleY(44);

  GetWindowsVersionEx(Version);
  if Version.Build >= 22000 then
    AddRow(GlyphGood, ColorGood, 'Windows 11, 64-bit', 'Supported.')
  else
    AddRow(GlyphGood, ColorGood, 'Windows 10, 64-bit', 'Supported.');

  Drive := ExtractFileDrive(ExpandConstant('{autopf}')) + '\';
  EnoughSpace := True;
  if GetSpaceOnDisk64(Drive, FreeBytes, TotalBytes) then
  begin
    FreeMB := FreeBytes div (1024 * 1024);
    EnoughSpace := FreeMB >= {#NeededMB};
    if EnoughSpace then
      AddRow(GlyphGood, ColorGood, 'Enough disk space',
        Format('LogAnalyser needs about %d MB; drive %s has %s free.', [{#NeededMB}, Copy(Drive, 1, 2), SizeText(FreeMB)]))
    else
      AddRow(GlyphBad, ColorBad, 'Not enough disk space', Format(
        'LogAnalyser needs about %d MB, but drive %s has only %s free. Free up some space, then run Setup again.', [{#NeededMB}, Copy(Drive, 1, 2), SizeText(FreeMB)]));
  end;

  NeedWebView2 := not WebView2Installed(WebViewVersion);
  if NeedWebView2 then
    AddRow(GlyphAction, ColorAction, 'Microsoft WebView2 Runtime: will be installed',
      'LogAnalyser uses it to show its window. Setup will download it from Microsoft (about 2 MB) and install it for you.')
  else
    AddRow(GlyphGood, ColorGood, 'Microsoft WebView2 Runtime',
      'Already installed (version ' + WebViewVersion + ').');

  if FileExists(ExpandConstant('{localappdata}\Programs\Ollama\ollama.exe')) then
    AddRow(GlyphGood, ColorGood, 'Ollama (optional)',
      'Found. You can use it for an AI second opinion that never leaves this computer.')
  else
    AddRow(GlyphInfo, clGrayText, 'Ollama (optional, not needed)',
      'Only for an AI second opinion that runs on this computer. You can add it, or an online AI, later in Settings.');

  if not EnoughSpace then
    SummaryLabel.Caption := 'LogAnalyser cannot be installed until the problem below is fixed.'
  else if NeedWebView2 then
    SummaryLabel.Caption := 'Your computer is almost ready. Setup will install the one missing part for you.'
  else
    SummaryLabel.Caption := 'Your computer is ready. Click Next to continue.';
  if not EnoughSpace then
    SummaryLabel.Font.Color := ColorBad
  else
    SummaryLabel.Font.Color := ColorGood;
end;

procedure InitializeWizard;
begin
  BuildCheckPage;
  DownloadPage := CreateDownloadPage('Getting Microsoft WebView2',
    'Setup is downloading a part LogAnalyser needs to show its window.', @OnDownloadProgress);
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = CheckPage.ID then
    WizardForm.NextButton.Enabled := EnoughSpace;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo,
  MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo;
  if MemoTasksInfo <> '' then
    Result := Result + NewLine + NewLine + MemoTasksInfo;
  if NeedWebView2 then
    Result := Result + NewLine + NewLine + 'Also install:' + NewLine + Space +
      'Microsoft WebView2 Runtime (downloaded from Microsoft)';
end;

{ Run Microsoft's WebView2 installer, already downloaded to Setup's temporary folder. A failure
  never stops the install: the app then opens in the web browser instead. }
procedure RunWebView2Setup;
var
  ResultCode: Integer;
  Version: String;
begin
  WebView2Done := True;
  Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  Log('WebView2 setup exit code: ' + IntToStr(ResultCode));
  if (ExpandConstant('{param:WEBVIEW2|auto}') <> 'missing') and not WebView2Installed(Version) then
    SuppressibleMsgBox('Microsoft WebView2 could not be installed (code ' + IntToStr(ResultCode) + '). ' +
      'LogAnalyser will still be installed, and will open in your web browser instead of its own window.',
      mbInformation, MB_OK, IDOK);
end;

procedure DownloadFailed(Reason: String);
begin
  WebView2Done := True;
  SuppressibleMsgBox('Setup could not download Microsoft WebView2: ' + Reason + #13#10#13#10 +
    'LogAnalyser will still be installed, and will open in your web browser instead of its own window. ' +
    'You can install WebView2 later from microsoft.com.', mbInformation, MB_OK, IDOK);
end;

{ With the wizard showing: download with a progress bar when Install is clicked. }
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID <> wpReady) or not NeedWebView2 or WebView2Done then
    Exit;
  DownloadPage.Clear;
  DownloadPage.Add('{#WebView2Url}', 'MicrosoftEdgeWebview2Setup.exe', '');
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
      DownloadPage.SetText('Installing Microsoft WebView2', 'This takes a minute or two. Please wait.');
      DownloadPage.ProgressBar.Style := npbstMarquee;
      DownloadPage.AbortButton.Hide;
      RunWebView2Setup;
    except
      if DownloadPage.AbortedByUser then
      begin
        WebView2Done := True;
        Log('WebView2 download cancelled.');
      end
      else
        DownloadFailed(GetExceptionMessage);
    end;
  finally
    DownloadPage.ProgressBar.Style := npbstNormal;
    DownloadPage.Hide;
  end;
end;

{ Silent installs (/SILENT, /VERYSILENT) skip the wizard pages, so they get WebView2 here. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not NeedWebView2 or WebView2Done then
    Exit;
  try
    DownloadTemporaryFile('{#WebView2Url}', 'MicrosoftEdgeWebview2Setup.exe', '', @OnDownloadProgress);
    RunWebView2Setup;
  except
    DownloadFailed(GetExceptionMessage);
  end;
end;

{ Move a folder to the Recycle Bin, so it can be restored. Uses the .NET method that Windows
  PowerShell has on every Windows 10 and 11 PC. Never deletes outright. }
function MoveToRecycleBin(Dir: String): Boolean;
var
  ResultCode: Integer;
  Quoted: String;
begin
  Quoted := Dir;
  StringChangeEx(Quoted, '''', '''''', True);
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName Microsoft.VisualBasic; ' +
    '[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(''' + Quoted + ''', ''OnlyErrorDialogs'', ''SendToRecycleBin'')"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Recycle Bin move exit code: ' + IntToStr(ResultCode));
  Result := not DirExists(Dir);
end;

{ Saved analyses and settings stay unless the person asks to remove them, and even then they go to
  the Recycle Bin. API keys live in the Windows Credential Manager and are not touched. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  DataDir := ExpandConstant('{userappdata}\{#AppName}');
  if not DirExists(DataDir) then
    Exit;
  if UninstallSilent then
    Exit;
  if MsgBox('Do you also want to move your saved analyses and LogAnalyser settings to the Recycle Bin?' + #13#10#13#10 +
    'Choose No to keep them for a later install. If you choose Yes, you can still restore them from the Recycle Bin.',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    if not MoveToRecycleBin(DataDir) then
      MsgBox('Your saved analyses and settings could not be moved to the Recycle Bin, so they were left in place:'
        + #13#10#13#10 + DataDir, mbInformation, MB_OK);
end;
