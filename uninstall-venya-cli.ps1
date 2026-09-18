# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

<#
.SYNOPSIS
    Venya Workstation CLI Uninstaller (Windows)

.DESCRIPTION
    Removes what install-venya-cli.ps1 created for the CURRENT user:
      - the venya-cli and venya-mcp uv tools (shims in %USERPROFILE%\.local\bin)
      - optionally %APPDATA%\venya (config + stored access token)

    No administrator rights required. Mirrors uninstall-venya-cli.sh.

    Environment variables:
      VENYA_SKIP_PROMPT  - "yes" skips the confirmation prompt
      VENYA_PURGE_CONFIG - "yes" also deletes %APPDATA%\venya
                           (default: ask; when non-interactive, config is KEPT)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall-venya-cli.ps1
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

function Info([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

$binDir  = Join-Path $env:USERPROFILE '.local\bin'
$uv      = Join-Path $binDir 'uv.exe'
$toolDir = Join-Path $env:APPDATA 'uv\tools'
$cfgDir  = Join-Path $env:APPDATA 'venya'
# Pre-gap-A builds wrote here; remove it too if present so no stale token survives.
$legacyCfgDir = Join-Path $env:USERPROFILE '.config\venya'

if ($env:VENYA_SKIP_PROMPT -ne 'yes') {
    $answer = Read-Host "Remove the venya CLI for user $env:USERNAME? [Y/n]"
    if ($answer -match '^[Nn]') { Info 'Aborted.'; exit 0 }
}

$purge = $env:VENYA_PURGE_CONFIG
if (-not $purge) {
    if (-not [Console]::IsInputRedirected) {
        $a = Read-Host "Also delete $cfgDir (server URL + stored access token)? [y/N]"
        if ($a -match '^[Yy]') { $purge = 'yes' } else { $purge = 'no' }
    } else {
        $purge = 'no'
        Info "Non-interactive: keeping $cfgDir (set VENYA_PURGE_CONFIG=yes to remove)."
    }
}

if (Test-Path $uv) {
    foreach ($t in 'venya-cli','venya-mcp') {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $uv tool uninstall $t 2>&1 | Out-Null
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) { Warn "uv tool uninstall reported nothing to remove ($t)." }
    }
} else {
    Warn 'uv not found - removing shims/venvs manually.'
}

# Belt and braces: uv tool uninstall normally clears both, but a partial or
# manual install can leave either behind, and a stale shim means a stale token path.
foreach ($t in 'venya-cli','venya-mcp') {
    $v = Join-Path $toolDir $t
    if (Test-Path $v) { Remove-Item -LiteralPath $v -Recurse -Force -ErrorAction SilentlyContinue }
}
foreach ($s in 'venya.exe','venya-mcp.exe') {
    $p = Join-Path $binDir $s
    if (Test-Path $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
}

if ($purge -eq 'yes') {
    foreach ($d in @($cfgDir, $legacyCfgDir)) {
        if (Test-Path $d) { Remove-Item -LiteralPath $d -Recurse -Force; Info "Removed $d" }
    }
}

# Fail loudly if anything still resolves - mirrors the .sh contract.
foreach ($s in 'venya.exe','venya-mcp.exe') {
    if (Test-Path (Join-Path $binDir $s)) { Fail "$s still present in $binDir - inspect manually." }
}

Info "Venya CLI uninstalled for $env:USERNAME."
Info "uv itself and the $binDir PATH entry were left in place (shared with other tools)."
