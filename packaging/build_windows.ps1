# Build the Windows app: dist\LogAnalyser\LogAnalyser.exe, a zip, and (if Inno Setup is installed) an installer.
# Run from the repository root:  powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true  # PowerShell 7.3+: a failing pip, PyInstaller or ISCC stops the build
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path ".venv")) { python -m venv .venv }
$py = Join-Path $root ".venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -e ".[desktop,build]"

& $py packaging\make_icons.py
& $py -m PyInstaller packaging\loganalyser.spec --noconfirm --clean --distpath dist --workpath build

$zip = "dist\LogAnalyser-1.1.0-Windows-portable.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "dist\LogAnalyser" -DestinationPath $zip
Write-Host "Portable app: $zip"

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc packaging\installer.iss
    Write-Host "Installer: dist\LogAnalyser-1.1.0-Windows-Setup.exe"
} else {
    Write-Host "Inno Setup not found, so no installer was made. Install it from https://jrsoftware.org/isinfo.php to get one."
}
