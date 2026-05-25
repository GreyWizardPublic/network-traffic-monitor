#!/usr/bin/env pwsh
# build-windows.ps1
# Native Windows build of ntm-client using MinGW-w64 (MSYS2 mingw64).
#
# Usage:
#   .\scripts\build-windows.ps1                    # Release build (default)
#   .\scripts\build-windows.ps1 -Clean             # Wipe build-windows/ first
#   .\scripts\build-windows.ps1 -Debug             # Debug build
#   .\scripts\build-windows.ps1 -RunTests          # Build + run unit tests
#   .\scripts\build-windows.ps1 -Clean -RunTests   # Clean build + run tests
#
# Prerequisites: run scripts\setup-toolchain-windows.ps1 once first.

param(
    [switch]$Clean,
    [switch]$Debug,
    [switch]$RunTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot    = Split-Path -Parent $PSScriptRoot
$BuildDir    = Join-Path $RepoRoot "build-windows"
$Toolchain   = Join-Path $RepoRoot "cmake\toolchain-windows-mingw64.cmake"
$NpcapSDK    = "C:/npcap-sdk"
$BuildType   = if ($Debug) { "Debug" } else { "Release" }
$Jobs        = $env:NUMBER_OF_PROCESSORS

Write-Host ""
Write-Host "=== ntm-client Windows Build ===" -ForegroundColor Cyan
Write-Host "  Build type : $BuildType"
Write-Host "  Build dir  : $BuildDir"
Write-Host "  Toolchain  : $Toolchain"
Write-Host "  Npcap SDK  : $NpcapSDK"
Write-Host "  Parallel   : $Jobs jobs"
Write-Host ""

# ── Verify prerequisites ───────────────────────────────────────────────────────
if (-not (Test-Path "C:\msys64\mingw64\bin\g++.exe")) {
    Write-Host "ERROR: MinGW-w64 g++ not found. Run scripts\setup-toolchain-windows.ps1 first." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "C:\npcap-sdk\Include\pcap.h")) {
    Write-Host "ERROR: Npcap SDK not found at C:\npcap-sdk. Run scripts\setup-toolchain-windows.ps1 first." -ForegroundColor Red
    exit 1
}

# ── Ensure MinGW64 is in PATH for this session ─────────────────────────────────
if ($env:PATH -notlike "*msys64\mingw64\bin*") {
    $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
}

# ── Clean ──────────────────────────────────────────────────────────────────────
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "[clean] Removing $BuildDir..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BuildDir
}

# ── Stale binary cleanup (CLAUDE.md § "Stale binary cleanup") ─────────────────
# Because the version is baked into the filename, a version bump leaves old
# binaries behind.  Remove them before configure so the wrong file is never
# deployed by mistake.
Remove-Item "$BuildDir\ntm-client-windows-amd64-*.exe" -ErrorAction SilentlyContinue

# ── Configure ─────────────────────────────────────────────────────────────────
Write-Host "[configure] Running cmake..." -ForegroundColor Yellow
cmake -B $BuildDir -G Ninja `
      -DCMAKE_TOOLCHAIN_FILE="$Toolchain" `
      -DNPCAP_SDK="$NpcapSDK" `
      -DCMAKE_BUILD_TYPE="$BuildType"

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: cmake configure failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# ── Build ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[build] Compiling..." -ForegroundColor Yellow
cmake --build $BuildDir -j $Jobs

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: cmake build failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# ── Run tests ─────────────────────────────────────────────────────────────────
if ($RunTests) {
    Write-Host ""
    Write-Host "[test] Running ntm-tests-windows..." -ForegroundColor Yellow
    $testExe = Join-Path $BuildDir "ntm-tests-windows.exe"
    if (-not (Test-Path $testExe)) {
        Write-Host "ERROR: test binary not found at $testExe" -ForegroundColor Red
        exit 1
    }
    # Redirect stderr to stdout before passing to Write-Host so PowerShell does
    # not wrap native-exe stderr lines as NativeCommandError objects, which
    # would set $? = $false and trigger $ErrorActionPreference = "Stop" even
    # when the test binary actually exits 0 (the false-positive bug).
    & $testExe 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: tests failed (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "[test] All tests passed." -ForegroundColor Green
}

# ── Report output ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Build successful ===" -ForegroundColor Green
$exes = Get-ChildItem -Path $BuildDir -Filter "ntm-client-windows-*.exe" -ErrorAction SilentlyContinue
if ($exes) {
    foreach ($exe in $exes) {
        $size = [math]::Round($exe.Length / 1MB, 2)
        Write-Host "  Output: $($exe.FullName)  ($size MB)" -ForegroundColor Green
    }
} else {
    Write-Host "  Output: $BuildDir\ntm-client-windows-amd64-*.exe" -ForegroundColor Green
}
if ($RunTests) {
    Write-Host "  Tests:  $BuildDir\ntm-tests-windows.exe  (all passed)" -ForegroundColor Green
}
Write-Host ""
