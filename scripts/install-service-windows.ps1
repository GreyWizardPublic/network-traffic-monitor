#!/usr/bin/env pwsh
# install-service-windows.ps1
# Install ntm-client as a Windows SCM service with a hardened 4-directory layout.
#
# Usage (from elevated PowerShell — must run as Administrator):
#   .\scripts\install-service-windows.ps1 [-BinaryPath <path>] [-ConfigPath <path>]
#
# Default paths:
#   Binary  : build-windows\ntm-client-windows-amd64-*.exe
#   Install : C:\Program Files\ntm-client\ntm-client.exe
#   Config  : C:\ProgramData\ntm-client\ntm-client.conf
#
# Directory layout created:
#   C:\Program Files\ntm-client\        <-- exe (service: rename-rights only)
#   C:\ProgramData\ntm-client\          <-- config, certs, state (service: read-only)
#   C:\ProgramData\ntm-client\staging\  <-- pending update downloads (service: full)
#   C:\ProgramData\ntm-client\secrets\  <-- identity key (service: read; Users: denied)

param(
    [string]$BinaryPath = "",
    [string]$ConfigPath = "C:\ProgramData\ntm-client\ntm-client.conf"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Require Administrator ──────────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "  Right-click PowerShell and choose 'Run as administrator', then retry." -ForegroundColor Red
    exit 1
}

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$InstallDir = "C:\Program Files\ntm-client"
$DataDir    = "C:\ProgramData\ntm-client"
$StagingDir = "$DataDir\staging"
$SecretsDir = "$DataDir\secrets"
$ServiceExe = "$InstallDir\ntm-client.exe"
$ServiceName = "ntm-client"

# ── Locate binary ──────────────────────────────────────────────────────────────
if ($BinaryPath -eq "") {
    $candidates = Get-ChildItem -Path "$RepoRoot\build-windows" `
                                -Filter "ntm-client-windows-amd64-*.exe" `
                                -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending
    if (-not $candidates) {
        Write-Host "ERROR: No ntm-client-windows-amd64-*.exe found in build-windows\." -ForegroundColor Red
        Write-Host "  Run: .\scripts\build-windows.ps1" -ForegroundColor Red
        exit 1
    }
    $BinaryPath = $candidates[0].FullName
}

if (-not (Test-Path $BinaryPath)) {
    Write-Host "ERROR: Binary not found: $BinaryPath" -ForegroundColor Red
    exit 1
}

$SigPath = $BinaryPath + ".sig"
if (-not (Test-Path $SigPath)) {
    Write-Host "ERROR: Signature file not found: $SigPath" -ForegroundColor Red
    Write-Host "  ntm-client verifies its own ML-DSA-65 signature at startup and" -ForegroundColor Red
    Write-Host "  refuses to start if the .sig file is missing." -ForegroundColor Red
    Write-Host "  Both the binary and its companion .sig file must be deployed together." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== ntm-client Service Installer ===" -ForegroundColor Cyan
Write-Host "  Binary  : $BinaryPath"
Write-Host "  Sig     : $SigPath"
Write-Host "  Install : $ServiceExe"
Write-Host "  Config  : $ConfigPath"
Write-Host ""

# ── Stop and remove existing service ──────────────────────────────────────────
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[setup] Stopping existing service..." -ForegroundColor Yellow
    if ($existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    Write-Host "[setup] Removing existing service registration..." -ForegroundColor Yellow
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# ── Create directory structure ─────────────────────────────────────────────────
foreach ($dir in @($InstallDir, $DataDir, $StagingDir, $SecretsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[setup] Created: $dir" -ForegroundColor Yellow
    }
}

# ── Copy binary + signature ───────────────────────────────────────────────────
# Both files are REQUIRED: ntm-client verifies its own ML-DSA-65 signature at
# Step 0 of startup and refuses to start (FATAL) if ntm-client.exe.sig is absent.
Write-Host "[setup] Installing binary and signature..." -ForegroundColor Yellow
Copy-Item -Path $BinaryPath -Destination $ServiceExe -Force
Copy-Item -Path $SigPath    -Destination ($ServiceExe + ".sig") -Force

# ── Apply hardened ACLs ────────────────────────────────────────────────────────
# Service SID: NT SERVICE\ntm-client (created when the service is registered)
# We set ACLs after sc.exe create so the service SID exists.
#
# Install dir  — SYSTEM:F, Administrators:F, NT SERVICE\ntm-client:(RX + rename rights)
# Data dir     — SYSTEM:F, Administrators:F, NT SERVICE\ntm-client:RX, Users:(none explicit)
# Staging dir  — SYSTEM:F, Administrators:F, NT SERVICE\ntm-client:F
# Secrets dir  — SYSTEM:F, Administrators:F, NT SERVICE\ntm-client:R, Users:(denied)
#
# Note: rename rights (used by MoveFileExW) require (M) on the directory.
# We grant (OI)(CI)(M) on InstallDir for the service SID.

# ── Register service ───────────────────────────────────────────────────────────
Write-Host "[setup] Registering Windows service..." -ForegroundColor Yellow
$binPath = "`"$ServiceExe`" --service --config `"$ConfigPath`""
& sc.exe create $ServiceName `
    binPath= $binPath `
    start= auto `
    DisplayName= "ntm-client Network Monitor" | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: sc.exe create failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

& sc.exe description $ServiceName "ntm-client packet monitor — network traffic telemetry" | Out-Null

# Failure actions: restart 3 times (5s / 5s / 30s), reset after 24h.
# The auto-updater calls ExitProcess(0) after a successful update; the SCM
# interprets this as a failure (non-zero exit or unexpected exit) and applies
# the restart policy, restarting with the new binary.
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

Write-Host "[setup] Applying hardened ACLs..." -ForegroundColor Yellow

# Strip inheritance and set explicit ACEs.
# Install dir: SYSTEM:F, Admins:F, NT SERVICE\ntm-client:(OI)(CI)(M) for rename/replace
icacls $InstallDir /inheritance:r `
    /grant:r "SYSTEM:(OI)(CI)F" `
    /grant:r "Administrators:(OI)(CI)F" `
    /grant:r "NT SERVICE\${ServiceName}:(OI)(CI)M" | Out-Null

# Data dir: SYSTEM:F, Admins:F, service:RX (read config and certs; write handled per-subdir)
icacls $DataDir /inheritance:r `
    /grant:r "SYSTEM:(OI)(CI)F" `
    /grant:r "Administrators:(OI)(CI)F" `
    /grant:r "NT SERVICE\${ServiceName}:(OI)(CI)RX" | Out-Null

# Staging dir: service has full access for download + state file writes
icacls $StagingDir /inheritance:r `
    /grant:r "SYSTEM:(OI)(CI)F" `
    /grant:r "Administrators:(OI)(CI)F" `
    /grant:r "NT SERVICE\${ServiceName}:(OI)(CI)F" | Out-Null

# Secrets dir: service read-only; deny Users
icacls $SecretsDir /inheritance:r `
    /grant:r "SYSTEM:(OI)(CI)F" `
    /grant:r "Administrators:(OI)(CI)F" `
    /grant:r "NT SERVICE\${ServiceName}:(OI)(CI)R" `
    /deny "BUILTIN\Users:(OI)(CI)(RX)" | Out-Null

# ── Create a minimal config if none exists ─────────────────────────────────────
if (-not (Test-Path $ConfigPath)) {
    Write-Host "[setup] Creating placeholder config at $ConfigPath..." -ForegroundColor Yellow
    $template = @"
# ntm-client configuration — edit before starting the service.
# See CLIENT_DEPLOYMENT.md for all available options.

server            = 127.0.0.1
port              = 5555
# identity        = C:\ProgramData\ntm-client\secrets\client_private.pem
# server_cert     = C:\ProgramData\ntm-client\server_cert.pem
# auto_update     = false
# transport       = tcp
"@
    $template | Out-File -FilePath $ConfigPath -Encoding utf8
}

# ── Start the service ──────────────────────────────────────────────────────────
Write-Host "[setup] Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName
Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Green
Write-Host "  Service : $ServiceName  ($($svc.Status))"
Write-Host "  Exe     : $ServiceExe"
Write-Host "  Config  : $ConfigPath"
Write-Host "  Data    : $DataDir"
Write-Host "  Secrets : $SecretsDir  (place client_private.pem here)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Edit $ConfigPath (set server, port, identity)."
Write-Host "  2. Place your Ed25519 key in $SecretsDir\client_private.pem"
Write-Host "  3. Run: Restart-Service $ServiceName"
Write-Host "  4. Check: Get-Service $ServiceName"
Write-Host ""
