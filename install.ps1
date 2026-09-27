# Clickboard installer for Windows 10 and 11.
#
#   irm https://raw.githubusercontent.com/wallisoft/clickboard/main/install.ps1 | iex
#
# Installs Python if it's missing, fetches Clickboard from GitHub into your
# user profile (no admin needed for that part), adds Start menu and startup
# shortcuts, asks once for admin to open Clickboard's ports in the firewall,
# then starts it. Re-running it updates Clickboard in place.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # makes downloads much faster in Windows PowerShell

$Source = "https://github.com/wallisoft/clickboard/archive/refs/heads/main.zip"
$Base   = Join-Path $env:LOCALAPPDATA "Clickboard"
$App    = Join-Path $Base "app"
$Venv   = Join-Path $Base "venv"

Write-Host "==> Installing Clickboard into $Base"

# --- 1. Python ----------------------------------------------------------------
function Find-Python {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        & py -3 --version *> $null
        if ($LASTEXITCODE -eq 0) { return @("py", "-3") }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    # Skip the Microsoft Store placeholder that only opens the Store.
    if ($python -and $python.Source -notlike "*WindowsApps*") { return @($python.Source) }
    return $null
}

$Py = Find-Python
if (-not $Py) {
    Write-Host "==> Python not found, installing Python 3.12 (one-off, takes a minute)"
    winget install -e --id Python.Python.3.12 --scope user --silent `
        --accept-package-agreements --accept-source-agreements
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "Machine")
    $Py = Find-Python
    if (-not $Py) {
        throw "Python installed, but this window can't see it yet. Close PowerShell, open a new one, and run the installer again."
    }
}
Write-Host "==> Using $(& $Py[0] $Py[1..9] --version)"

# --- 2. Stop a running copy so files can be replaced ----------------------------
try {
    $client = New-Object Net.Sockets.TcpClient("127.0.0.1", 47801)
    $bytes = [Text.Encoding]::ASCII.GetBytes("quit`n")
    $client.GetStream().Write($bytes, 0, $bytes.Length)
    $client.Close()
    Write-Host "==> Stopped the running copy"
    Start-Sleep -Seconds 2
} catch { }

# --- 3. Fetch Clickboard ------------------------------------------------------
$zip = Join-Path $env:TEMP "clickboard-main.zip"
$tmp = Join-Path $env:TEMP "clickboard-extract"
Write-Host "==> Downloading the latest Clickboard"
Invoke-WebRequest $Source -OutFile $zip -UseBasicParsing
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive $zip -DestinationPath $tmp -Force
Remove-Item $App -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Base | Out-Null
Move-Item (Join-Path $tmp "clickboard-main") $App
Remove-Item $zip, $tmp -Recurse -Force -ErrorAction SilentlyContinue

# --- 4. Private Python environment ----------------------------------------------
if (-not (Test-Path (Join-Path $Venv "Scripts\pythonw.exe"))) {
    Write-Host "==> Creating Clickboard's own Python environment"
    & $Py[0] $Py[1..9] -m venv $Venv
}
$VenvPy  = Join-Path $Venv "Scripts\python.exe"
$VenvPyw = Join-Path $Venv "Scripts\pythonw.exe"
Write-Host "==> Installing libraries"
& $VenvPy -m pip install --quiet --disable-pip-version-check -r (Join-Path $App "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Installing libraries failed. Check your internet connection and try again." }

# --- 5. Shortcuts: Start menu, and start at sign-in ------------------------------
$shell  = New-Object -ComObject WScript.Shell
$script = Join-Path $App "clickboard.py"
foreach ($folder in @([Environment]::GetFolderPath("Programs"), [Environment]::GetFolderPath("Startup"))) {
    $lnk = $shell.CreateShortcut((Join-Path $folder "Clickboard.lnk"))
    $lnk.TargetPath = $VenvPyw
    $lnk.Arguments = "`"$script`""
    $lnk.WorkingDirectory = $App
    $lnk.Description = "The clipboard that follows you between machines"
    $lnk.Save()
}
Write-Host "==> Added Clickboard to the Start menu and to start when you sign in"

# --- 6. Firewall (one admin prompt) ----------------------------------------------
$fw = @"
Remove-NetFirewallRule -DisplayName 'Clickboard (TCP 47800)' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Clickboard local discovery (UDP 47802)' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Clickboard (TCP 47800)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47800 -Profile Private,Domain | Out-Null
New-NetFirewallRule -DisplayName 'Clickboard local discovery (UDP 47802)' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 47802 -Profile Private,Domain | Out-Null
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($fw))
Write-Host "==> Windows will ask for admin permission once, to let your machines reach each other"
try {
    Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList "-NoProfile -EncodedCommand $encoded"
    Write-Host "==> Firewall opened for Clickboard on private networks"
} catch {
    Write-Host "    Skipped. Windows will ask again the first time Clickboard runs; choose Private networks."
}

# --- 7. Start it -------------------------------------------------------------------
Start-Process $VenvPyw -ArgumentList "`"$script`"" -WorkingDirectory $App
Write-Host ""
Write-Host "Done. Clickboard is running: look for the dot in the system tray (you may need the ^ arrow)."
Write-Host "Logs: $env:APPDATA\Clickboard\clickboard.log"
