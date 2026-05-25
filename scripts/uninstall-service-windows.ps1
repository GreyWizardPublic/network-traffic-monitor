#!/usr/bin/env pwsh
# uninstall-service-windows.ps1
# Remove the ntm-client Windows service registration and binary.
# Config, identity key, and data directory are preserved.
#
# Usage (from elevated PowerShell — must run as Administrator):
#   .\scripts\uninstall-service-windows.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

$ServiceName = "ntm-client"
$InstallDir  = "C:\Program Files\ntm-client"

Write-Host ""
Write-Host "=== ntm-client Service Uninstaller ===" -ForegroundColor Cyan
Write-Host "  Preserves: C:\ProgramData\ntm-client\ (config, keys, state)"
Write-Host ""

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "Service '$ServiceName' is not installed." -ForegroundColor Yellow
} else {
    if ($svc.Status -eq "Running") {
        Write-Host "[uninstall] Stopping service..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    Write-Host "[uninstall] Removing service registration..." -ForegroundColor Yellow
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: sc.exe delete failed (exit $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
    Write-Host "[uninstall] Service removed." -ForegroundColor Green
}

# Remove install directory (exe only; data/config is preserved).
if (Test-Path $InstallDir) {
    Write-Host "[uninstall] Removing install directory $InstallDir..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $InstallDir
}

Write-Host ""
Write-Host "=== Uninstall complete ===" -ForegroundColor Green
Write-Host "  Config and identity key preserved at C:\ProgramData\ntm-client\"
Write-Host "  Remove manually if no longer needed:"
Write-Host "    Remove-Item -Recurse -Force 'C:\ProgramData\ntm-client'"
Write-Host ""
