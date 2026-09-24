# windows-build-seed.ps1 - release the Windows build-key seed to a caller's pipe.
#
# Reads %USERPROFILE%\.ntm\windows-build.dpapi (created in #135), decrypts it
# with DPAPI (CurrentUser scope) and writes the ML-DSA-65 seed to stdout as
# exactly 64 lowercase hex characters: no newline, nothing else. Exit 0.
#
# On any failure: one-line reason on stderr, nothing on stdout, exit 1.
# The reason never includes file content.
#
# Called by the MSYS2 signing script (trust v2, #133 phase 3) as:
#   "$(cygpath -u "$SYSTEMROOT")/System32/WindowsPowerShell/v1.0/powershell.exe" \
#       -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<win path to this file>"
# The caller strips any trailing \r.
#
# Windows PowerShell 5.1. Keep this file ASCII-only (project-rules section 9).
# Never Write-Host / Write-Output the seed: stdout is written once, via
# [Console]::Out, and only after validation.

$ErrorActionPreference = 'Stop'

function Fail([string]$reason) {
    [Console]::Error.WriteLine("windows-build-seed: $reason")
    exit 1
}

$path = Join-Path $env:USERPROFILE '.ntm\windows-build.dpapi'
if (-not $env:USERPROFILE -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
    Fail "build key not found at $path (see #135)"
}

try {
    $secure = Get-Content -LiteralPath $path -Raw | ConvertTo-SecureString
} catch {
    Fail "DPAPI decrypt failed (wrong user or corrupt file)"
}

$ptr = [IntPtr]::Zero
try {
    $ptr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $seed = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if ($seed -cnotmatch '^[0-9a-f]{64}$') {
        Fail "decrypted content is not 64 lowercase hex characters"
    }
    [Console]::Out.Write($seed)
    [Console]::Out.Flush()
} finally {
    if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    Remove-Variable seed -ErrorAction SilentlyContinue
    $secure.Dispose()
}
exit 0
