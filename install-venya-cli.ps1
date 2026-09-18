# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

<#
.SYNOPSIS
    Venya Workstation CLI Installer (Windows)

.DESCRIPTION
    Installs the Venya workstation client bundle for the CURRENT user:
      - uv (if missing) into %USERPROFILE%\.local\bin
      - venya-cli via `uv tool install` (isolated venv, `venya` shim)
      - venya-mcp via `uv tool install` (isolated venv, `venya-mcp` shim;
        set VENYA_INSTALL_MCP=no to skip)

    No administrator rights required. Mirrors install-venya-cli.sh.

    Environment variables:
      VENYA_SKIP_PROMPT     - "yes" skips the confirmation prompt
      VENYA_INSTALL_MCP     - "no" installs only the CLI (default: both)
      VENYA_TARBALL         - URL of the venya-cli tarball (default: latest
                              GitHub release asset)
      VENYA_TARBALL_SHA256  - Pin the expected sha256 (recommended: strict
                              integrity). If unset, the installer fetches
                              <tarball-url>.sha256 from the same origin as a
                              corruption guardrail; fail-closed.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install-venya-cli.ps1
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

# PowerShell 5.1 on older Windows 10 can default below TLS 1.2, which GitHub
# and astral.sh both reject. Explicit, so the failure class cannot occur.
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Info([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

# Native executables do not raise on failure and their stderr becomes a
# PowerShell ErrorRecord under $ErrorActionPreference='Stop'. Both are handled
# here: stderr is allowed through as text, and the exit code is checked, so no
# step can fail silently.
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory)][string]$What
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Exe @Arguments } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { Fail "$What failed (exit $LASTEXITCODE)." }
}

function Get-SystemTool([string]$name) {
    $p = Join-Path $env:SystemRoot "System32\$name"
    if (-not (Test-Path $p)) { Fail "Required Windows component not found: $p" }
    return $p
}

$curl = Get-SystemTool 'curl.exe'
$tar  = Get-SystemTool 'tar.exe'

$tarballUrl = if ($env:VENYA_TARBALL) { $env:VENYA_TARBALL } else {
    'https://github.com/tabith-llc/venya/releases/latest/download/venya-cli-install.tar.gz'
}

Info "Installing Venya CLI for $env:USERNAME..."

if ($env:VENYA_SKIP_PROMPT -ne 'yes') {
    $answer = Read-Host "Install venya CLI for user $env:USERNAME? [Y/n]"
    if ($answer -match '^[Nn]') { Info 'Aborted.'; exit 0 }
}

# --- uv (per-user) ---
$binDir = Join-Path $env:USERPROFILE '.local\bin'
$uv = Join-Path $binDir 'uv.exe'

if (-not (Test-Path $uv)) {
    Info 'Installing uv...'
    try {
        $installPs1 = (Invoke-WebRequest -Uri 'https://astral.sh/uv/install.ps1' -UseBasicParsing).Content
    } catch {
        Fail "Cannot fetch the uv installer: $($_.Exception.Message)"
    }
    Invoke-Expression $installPs1
    if (-not (Test-Path $uv)) { Fail "uv install completed but $uv was not found." }
} else {
    Info "uv already installed: $(& $uv --version)"
}

# uv persisted .local\bin into the user PATH, but this session started before
# that happened, so the shims are not resolvable here yet.
$env:Path = "$binDir;$env:Path"

# --- Download + verify (sha256: explicit pin, else same-origin sidecar; fail-closed) ---
$workDir = Join-Path $env:TEMP ("venya-cli-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    $tarballFile = Join-Path $workDir 'venya-cli-install.tar.gz'
    Info "Downloading tarball from $tarballUrl..."
    Invoke-Native -Exe $curl -Arguments @('-fsSL', '-o', $tarballFile, $tarballUrl) -What "Download of $tarballUrl"

    $expected = $env:VENYA_TARBALL_SHA256
    if (-not $expected) {
        Info 'VENYA_TARBALL_SHA256 not set - fetching checksum sidecar from origin...'
        $sidecarFile = Join-Path $workDir 'tarball.sha256'
        Invoke-Native -Exe $curl -Arguments @('-fsSL', '-o', $sidecarFile, "$tarballUrl.sha256") -What "Sidecar fetch ${tarballUrl}.sha256 - refusing to install without integrity verification (set VENYA_TARBALL_SHA256 to pin the expected hash)"
        $line = Get-Content -LiteralPath $sidecarFile -TotalCount 1
        $expected = ($line -split '\s+')[0]
        if (-not $expected) { Fail "Sidecar ${tarballUrl}.sha256 contained no hash. Aborting." }
    }

    Info 'Verifying tarball SHA-256...'
    # Get-FileHash emits uppercase and the sidecar is lowercase; normalise both
    # or the comparison can never succeed.
    $actual = (Get-FileHash -LiteralPath $tarballFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedNorm = $expected.Trim().ToLowerInvariant()
    if ($actual -ne $expectedNorm) {
        Fail @"
Tarball SHA-256 mismatch!
  Expected: $expectedNorm
  Actual:   $actual
Possible MITM or corrupted download. Aborting.
"@
    }
    Info 'SHA-256 verified.'

    # --- Extract (workstation bundle: packages/cli + packages/mcp) ---
    # The archive is built with `git archive --prefix=./`, so members are
    # already at the top level. No --strip-components, unlike the core and
    # executor installers.
    $extractDir = Join-Path $workDir 'src'
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Invoke-Native -Exe $tar -Arguments @('xzf', $tarballFile, '-C', $extractDir) -What 'Tarball extraction'
    Remove-Item -LiteralPath $tarballFile -Force

    $cliProject = Join-Path $extractDir 'packages\cli\pyproject.toml'
    if (-not (Test-Path $cliProject)) {
        Fail 'Tarball layout unexpected: packages/cli/pyproject.toml not found.'
    }

    # --- Install via uv tool (isolated venvs + .local\bin shims) ---
    Info 'Installing venya-cli via uv tool...'
    Invoke-Native -Exe $uv -Arguments @('tool', 'install', '--force', '--python', '3.14', (Join-Path $extractDir 'packages\cli')) -What 'uv tool install venya-cli'

    $installMcp = if ($env:VENYA_INSTALL_MCP) { $env:VENYA_INSTALL_MCP } else { 'yes' }
    if ($installMcp -ne 'no') {
        $mcpProject = Join-Path $extractDir 'packages\mcp\pyproject.toml'
        if (-not (Test-Path $mcpProject)) {
            Fail 'Tarball layout unexpected: packages/mcp/pyproject.toml not found (VENYA_INSTALL_MCP != no).'
        }
        Info 'Installing venya-mcp via uv tool...'
        Invoke-Native -Exe $uv -Arguments @('tool', 'install', '--force', '--python', '3.14', (Join-Path $extractDir 'packages\mcp')) -What 'uv tool install venya-mcp'
    }

    # --- Verify ---
    $venyaExe = Join-Path $binDir 'venya.exe'
    if (-not (Test-Path $venyaExe)) {
        Fail "venya shim not found at $venyaExe after install. Open a new terminal, or run: uv tool update-shell"
    }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $venyaExe --help *> $null
    $helpExit = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($helpExit -ne 0) { Fail "venya --help failed (exit $helpExit)." }
    Info "venya CLI installed: $venyaExe"

    if ($installMcp -ne 'no') {
        $mcpExe = Join-Path $binDir 'venya-mcp.exe'
        if (-not (Test-Path $mcpExe)) { Fail "venya-mcp shim not found at $mcpExe after install." }
        # No --help probe: venya-mcp is a stdio server and would block. Import check.
        # Windows venvs place the interpreter in Scripts\, not bin/.
        $toolDir = (& $uv tool dir | Out-String).Trim()
        $mcpPython = Join-Path $toolDir 'venya-mcp\Scripts\python.exe'
        if (Test-Path $mcpPython) {
            Invoke-Native -Exe $mcpPython -Arguments @('-c', 'import venya_mcp.server') -What 'venya-mcp server module import'
        } else {
            Warn "Could not locate the venya-mcp venv interpreter at $mcpPython; skipped the import check."
        }
        Info "venya-mcp installed: $mcpExe"
    }
} finally {
    if (Test-Path $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- FIDO2 access check ---
# fido2 ships a native Windows HID backend (fido2/hid/windows.py, pure ctypes
# against hid.dll/setupapi.dll), so there is no libusb, no Zadig and no driver
# setup. Administrator rights ARE currently required, see the warning below.
Info 'FIDO2 on Windows uses the native HID backend - no driver setup, no libusb, no Zadig.'
Warn 'LIMITATION: since Windows 10 1903 the OS restricts raw CTAP/HID access to'
Warn 'elevated processes (documented by python-fido2 itself). Until the platform'
Warn 'WebAuthn API path lands, these commands must be run from an ADMINISTRATOR'
Warn 'terminal, and only in an interactive desktop session:'
Warn '    venya init / venya login / venya credential add'
Warn 'They will not work over SSH or WinRM (no foreground window), and a standard'
Warn 'non-admin user will see a misleading "No FIDO2 devices found".'
Warn 'Tracked as ticket windows-fido2-requires-elevation.'
Info 'Plug in the security key before the first venya login/enroll.'

$caCert = Join-Path $env:APPDATA 'venya\venya-ca.crt'

Write-Host ''
Write-Host '============================================'
Write-Host "  Venya CLI installed for $env:USERNAME"
Write-Host '============================================'
Write-Host ''
Write-Host 'Day-one commands (open a NEW terminal so PATH refreshes):'
Write-Host '  venya config set-server https://<core-host>'
Write-Host "  curl.exe -sk https://<core-host>/.well-known/venya-ca.crt -o `"$caCert`""
Write-Host "  `$env:SSL_CERT_FILE=`"$caCert`"; venya init <user-id>    # first admin account (FIDO2 key required)"
Write-Host "  `$env:SSL_CERT_FILE=`"$caCert`"; venya login <user-id>"
if ($installMcp -ne 'no') {
    Write-Host ''
    Write-Host 'MCP (LLM clients) - point the client at the venya-mcp shim and provide:'
    Write-Host "  VENYA_CONFIG=$env:APPDATA\venya\config.json  (server_url + access_token from venya login)"
    Write-Host "  VENYA_CA_CERT=$caCert  (required at startup)"
}
Write-Host ''
