#!/usr/bin/env pwsh
# setup-toolchain-windows.ps1
# One-time setup of the native Windows build toolchain for ntm-client.
# Run once from PowerShell (as Administrator for PATH changes):
#   .\scripts\setup-toolchain-windows.ps1
#
# What it does:
#   1. Verifies MSYS2 + MinGW-w64 packages are installed
#   2. Adds C:\msys64\mingw64\bin to the system PATH (machine-wide)
#   3. Verifies Npcap SDK is present at C:\npcap-sdk
#   4. Prints a ready-to-paste cmake configure command

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$MSYS2_BIN   = "C:\msys64\usr\bin\bash.exe"
$MINGW64_BIN = "C:\msys64\mingw64\bin"
$NPCAP_SDK   = "C:\npcap-sdk"

Write-Host ""
Write-Host "=== ntm-client Windows Toolchain Setup ===" -ForegroundColor Cyan
Write-Host ""

# ── 1. MSYS2 ──────────────────────────────────────────────────────────────────
Write-Host "[1/4] Checking MSYS2..." -ForegroundColor Yellow
if (-not (Test-Path $MSYS2_BIN)) {
    Write-Host "  ERROR: MSYS2 not found at C:\msys64" -ForegroundColor Red
    Write-Host "  Install with: winget install MSYS2.MSYS2"
    exit 1
}
Write-Host "  OK: MSYS2 found" -ForegroundColor Green

# ── 2. MinGW-w64 packages ─────────────────────────────────────────────────────
Write-Host "[2/4] Checking MinGW-w64 packages..." -ForegroundColor Yellow
$required = @("gcc.exe", "g++.exe", "ninja.exe", "cmake.exe", "windres.exe")
$missing  = @()
foreach ($exe in $required) {
    if (Test-Path "$MINGW64_BIN\$exe") {
        Write-Host "  OK: $exe" -ForegroundColor Green
    } else {
        Write-Host "  MISSING: $exe" -ForegroundColor Red
        $missing += $exe
    }
}
if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "  Installing missing packages via pacman..." -ForegroundColor Yellow
    & $MSYS2_BIN -lc "pacman -S --noconfirm --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-openssl mingw-w64-x86_64-make"
    Write-Host "  Done." -ForegroundColor Green
}

# ── 3. PATH ───────────────────────────────────────────────────────────────────
Write-Host "[3/4] Checking PATH..." -ForegroundColor Yellow
$machinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($machinePath -notlike "*$MINGW64_BIN*") {
    Write-Host "  Adding $MINGW64_BIN to system PATH..." -ForegroundColor Yellow
    [System.Environment]::SetEnvironmentVariable(
        "PATH",
        "$MINGW64_BIN;$machinePath",
        "Machine"
    )
    $env:PATH = "$MINGW64_BIN;" + $env:PATH
    Write-Host "  OK: Added (restart terminal for full effect)" -ForegroundColor Green
} else {
    Write-Host "  OK: Already in PATH" -ForegroundColor Green
}

# ── 4. Npcap SDK ──────────────────────────────────────────────────────────────
Write-Host "[4/4] Checking Npcap SDK..." -ForegroundColor Yellow
if (-not (Test-Path "$NPCAP_SDK\Include\pcap.h")) {
    Write-Host "  ERROR: Npcap SDK not found at $NPCAP_SDK" -ForegroundColor Red
    Write-Host "  Download from https://npcap.com/#download"
    Write-Host "  Extract the zip so that $NPCAP_SDK\Include\pcap.h exists."
    exit 1
}
$wpcapLib = "$NPCAP_SDK\Lib\x64\wpcap.lib"
if (-not (Test-Path $wpcapLib)) {
    Write-Host "  ERROR: wpcap.lib not found at $wpcapLib" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: Npcap SDK found (pcap.h + wpcap.lib)" -ForegroundColor Green

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Toolchain ready! ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Build commands (from repo root in PowerShell):" -ForegroundColor White
Write-Host ""
Write-Host '  .\scripts\build-windows.ps1' -ForegroundColor Green
Write-Host ""
Write-Host "Or manually:" -ForegroundColor White
Write-Host ""
Write-Host "  cmake -B build-windows -G Ninja ``" -ForegroundColor DarkGray
Write-Host "        -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-windows-mingw64.cmake ``" -ForegroundColor DarkGray
Write-Host "        -DNPCAP_SDK=C:/npcap-sdk ``" -ForegroundColor DarkGray
Write-Host "        -DCMAKE_BUILD_TYPE=Release" -ForegroundColor DarkGray
Write-Host "  cmake --build build-windows -j `$env:NUMBER_OF_PROCESSORS" -ForegroundColor DarkGray
Write-Host ""
