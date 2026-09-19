# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

<#
.SYNOPSIS
    Venya Workstation CLI Uninstaller (Windows, machine-wide)

.DESCRIPTION
    Removes what install-venya-cli.ps1 created:
      - the whole install root (default C:\Program Files\Venya) — pinned uv,
        uv-managed Python, both tool venvs and the shims
      - the install root's bin directory from the MACHINE PATH
      - optionally the INVOKING user's %APPDATA%\venya (config + access token)

    REQUIRES ADMINISTRATOR RIGHTS, matching the installer.

    Per-user config for OTHER users is not removed: it lives in each user's own
    profile, which this script does not enumerate. Those files contain an access
    token, so the command to find them is printed instead of being run silently.

    Environment variables:
      VENYA_SKIP_PROMPT  - "yes" skips the confirmation prompt
      VENYA_PURGE_CONFIG - "yes" also deletes the invoking user's %APPDATA%\venya
                           (default: ask; when non-interactive, config is KEPT)
      VENYA_INSTALL_DIR  - install root to remove (must match the installer)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall-venya-cli.ps1
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

function Info([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail @"
Administrator rights are REQUIRED to uninstall the machine-wide Venya CLI.
Re-run from an elevated terminal: right-click PowerShell -> Run as administrator.
"@
}

$Base   = if ($env:VENYA_INSTALL_DIR) { $env:VENYA_INSTALL_DIR } else { 'C:\Program Files\Venya' }
$BinDir = Join-Path $Base 'bin'
$cfgDir = Join-Path $env:APPDATA 'venya'

Info "Removing the machine-wide Venya CLI from $Base"

if ($env:VENYA_SKIP_PROMPT -ne 'yes') {
    $answer = Read-Host "Remove the Venya CLI for ALL users of this machine? [Y/n]"
    if ($answer -match '^[Nn]') { Info 'Aborted.'; exit 0 }
}

$purge = $env:VENYA_PURGE_CONFIG
if (-not $purge) {
    if (-not [Console]::IsInputRedirected) {
        $a = Read-Host "Also delete YOUR config at $cfgDir (server URL + stored access token)? [y/N]"
        if ($a -match '^[Yy]') { $purge = 'yes' } else { $purge = 'no' }
    } else {
        $purge = 'no'
        Info "Non-interactive: keeping $cfgDir (set VENYA_PURGE_CONFIG=yes to remove)."
    }
}

if (Test-Path $Base) {
    Remove-Item -LiteralPath $Base -Recurse -Force
    Info "Removed $Base"
} else {
    Warn "Install root $Base not present - nothing to remove there."
}

# Remove only our own entry, preserving the rest of the machine PATH verbatim.
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath) {
    $parts = $machinePath -split ';' | Where-Object { $_ -and ($_ -ne $BinDir) }
    $newPath = ($parts -join ';')
    if ($newPath -ne $machinePath) {
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
        Info "Removed $BinDir from the MACHINE PATH."
    } else {
        Info "Machine PATH did not contain $BinDir"
    }
}

if ($purge -eq 'yes') {
    if (Test-Path $cfgDir) { Remove-Item -LiteralPath $cfgDir -Recurse -Force; Info "Removed $cfgDir" }
    $legacy = Join-Path $env:USERPROFILE '.config\venya'
    if (Test-Path $legacy) { Remove-Item -LiteralPath $legacy -Recurse -Force; Info "Removed $legacy (pre-%APPDATA% build)" }
}

# Fail loudly if a shim still resolves anywhere - mirrors the .sh contract.
foreach ($s in 'venya.exe','venya-mcp.exe') {
    $p = Join-Path $BinDir $s
    if (Test-Path $p) { Fail "$s still present at $p - inspect manually." }
}
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
foreach ($s in 'venya','venya-mcp') {
    $c = Get-Command $s -ErrorAction SilentlyContinue
    if ($c) { Fail "$s still resolves at $($c.Source) - inspect manually." }
}

Warn 'Per-user config for OTHER users was NOT removed. Each holds an access token at:'
Warn '  %APPDATA%\venya\config.json'
Warn 'To find them (admin, read-only listing):'
Warn '  Get-ChildItem C:\Users\*\AppData\Roaming\venya\config.json -ErrorAction SilentlyContinue'

Info 'Venya CLI uninstalled machine-wide.'
