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

    A removal root that is itself a junction or a symlink is REFUSED before anything is
    touched (#755/#758), matching the bash uninstallers: removing the link name would
    report an uninstall while the tree it points at stayed on the machine.

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

$Base    = if ($env:VENYA_INSTALL_DIR) { $env:VENYA_INSTALL_DIR } else { 'C:\Program Files\Venya' }
$BinDir  = Join-Path $Base 'bin'
$ToolDir = Join-Path $Base 'uv-tools'
$cfgDir  = Join-Path $env:APPDATA 'venya'
$legacy  = Join-Path $env:USERPROFILE '.config\venya'

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

# A removal root that is itself a reparse point (a junction or a symlink) is not this
# machine's Venya root. Remove-Item -Recurse -Force deletes the LINK NAME and succeeds, so
# the run used to claim an uninstall while the tree the link pointed at stood untouched — the
# same shape #755 refused on the core state paths and #758 on the config dir. The probe is
# Get-Item -Force, an lstat: a link whose target is already gone still reads here as an
# item, where a presence test would read "missing" and walk past it. The scope is the root
# itself, not what lives under it: uv needs a junction inside the install root for its
# Python minor-version alias (see install-venya-cli.ps1), and that entry goes as the link
# it is. Order matches the removals below — $Base first, then the two config roots, and
# those only when the config purge is actually in scope.
$guardRoots = @($Base)
if ($purge -eq 'yes') { $guardRoots += $cfgDir, $legacy }
foreach ($root in $guardRoots) {
    try { $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop } catch { continue }
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { continue }
    # LinkType and Target are PowerShell 6+ properties; 5.1 carries neither, so a 5.1 run
    # names the path and the fact that it is a link rather than guessing at the rest.
    $rootWhat = 'reparse point'
    if ($rootItem.PSObject.Properties.Name -contains 'LinkType') { $rootWhat = $rootItem.LinkType }
    if ($rootItem.PSObject.Properties.Name -contains 'Target') {
        $rootTarget = @( $rootItem.Target )[0]
        if ($rootTarget) { $rootWhat = "$rootWhat -> $rootTarget" }
    }
    Fail @"
$root is a $rootWhat - refusing to remove through it (#755/#758).
Nothing was removed: that path is not a real Venya directory. Repoint it at a directory on
this machine, or remove what it points at yourself, then re-run this uninstaller.
"@
}

if (Test-Path -LiteralPath $Base) {
    Remove-Item -LiteralPath $Base -Recurse -Force
    # No "Removed" claim here: #402 gates every success claim on the
    # verify-absent loop below (the #396 bash contract).
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
    if (Test-Path -LiteralPath $cfgDir) { Remove-Item -LiteralPath $cfgDir -Recurse -Force; Info "Removed $cfgDir" }
    if (Test-Path -LiteralPath $legacy) { Remove-Item -LiteralPath $legacy -Recurse -Force; Info "Removed $legacy (pre-%APPDATA% build)" }
}

# #402 verify-absent (mirrors the #396 bash contract): re-test every declared
# removal site after the fact; a survivor - e.g. a locked file left by a
# partial removal - fails loud naming its path. The success claim below is
# reachable only through this loop. The uv tool list probe is not cheaply
# applicable here: the pinned uv.exe lives under $Base, so a verified-absent
# $Base leaves no machine-wide tool entries to list, and a surviving $Base
# already fails the loop.
foreach ($p in @($Base,
                 (Join-Path $ToolDir 'venya-cli'),
                 (Join-Path $ToolDir 'venya-mcp'),
                 (Join-Path $BinDir 'venya.exe'),
                 (Join-Path $BinDir 'venya-mcp.exe'))) {
    if (Test-Path -LiteralPath $p) { Fail "Still present after removal: $p - inspect manually." }
}
# A shim that still resolves is classified, not simply failed (#755/#758). The verify-absent
# loop above is what establishes that this run's removal happened, and it is unchanged: a
# survivor under $Base exits 1 there, before this sweep ever runs. So a hit here answers a
# different question — which venya is answering — and the two arms say which one they saw.
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
$removedPrefix = $Base.TrimEnd('\') + '\'
foreach ($s in 'venya','venya-mcp') {
    $c = Get-Command $s -ErrorAction SilentlyContinue
    if (-not $c) { continue }
    if (-not $c.Source) { Fail "$s still resolves from an unknown source - inspect manually." }
    if ($c.Source.StartsWith($removedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        # Still under the root this run removed: a real survivor, and it fails loud.
        Fail "$s still resolves at $($c.Source) - inside the removed root $Base; inspect manually."
    }
    # Elsewhere: a second install the operator never asked to remove. Naming it is the whole
    # report — this run did what it was told, and the machine is not clean.
    Warn "$s still resolves at $($c.Source) - a different install root than the one removed ($Base); the removal asked for here completed."
}

Warn 'Per-user config for OTHER users was NOT removed. Each holds an access token at:'
Warn '  %APPDATA%\venya\config.json'
Warn 'To find them (admin, read-only listing):'
Warn '  Get-ChildItem C:\Users\*\AppData\Roaming\venya\config.json -ErrorAction SilentlyContinue'

Info 'Venya CLI uninstalled machine-wide.'
