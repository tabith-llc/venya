# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

<#
.SYNOPSIS
    Venya Workstation CLI Installer (Windows, machine-wide)

.DESCRIPTION
    Installs the Venya workstation client bundle ONCE FOR THE WHOLE MACHINE:
      - a pinned uv binary (verified by sha256) under the install root
      - a uv-managed CPython 3.14
      - venya-cli and venya-mcp as isolated uv tool venvs
      - `venya` and `venya-mcp` shims on the MACHINE PATH

    REQUIRES ADMINISTRATOR RIGHTS. This is deliberate, not an oversight:
    Windows 10 1903+ refuses to let a standard (Medium integrity) user traverse a
    junction that a standard user created, and uv needs a junction for its Python
    minor-version alias. An admin-created junction IS traversable by standard
    users, so a machine-wide admin install works for everyone while a per-user
    install cannot. See ticket windows-uv-junction-standard-user.

    Standard users need no rights to USE the CLI. Per-user state (server URL,
    access token) still lives in each user's own %APPDATA%\venya\config.json.

    Environment variables:
      VENYA_SKIP_PROMPT     - "yes" skips the confirmation prompt
      VENYA_INSTALL_MCP     - "no" installs only the CLI (default: both)
      VENYA_INSTALL_DIR     - install root (default: C:\Program Files\Venya)
      VENYA_UV_VERSION      - pinned uv version (default: 0.12.17)
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
# rejects. Explicit, so the failure class cannot occur.
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Info([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

# Native executables do not raise on failure, and their stderr becomes a
# PowerShell ErrorRecord under $ErrorActionPreference='Stop'. Both are handled
# here so no step can fail silently.
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

# --- Elevation is a hard requirement ---
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail @"
Administrator rights are REQUIRED to install the Venya CLI on Windows.
This installs machine-wide (once per machine, by IT), not per user.
Reason: Windows 10 1903+ will not let a standard user traverse a junction that a
standard user created, and uv needs one for its Python minor-version alias.
Re-run from an elevated terminal: right-click PowerShell -> Run as administrator.
"@
}

$curl = Get-SystemTool 'curl.exe'
$tar  = Get-SystemTool 'tar.exe'

$Base      = if ($env:VENYA_INSTALL_DIR) { $env:VENYA_INSTALL_DIR } else { 'C:\Program Files\Venya' }
$UvDir     = Join-Path $Base 'uv'
$UvExe     = Join-Path $UvDir 'uv.exe'
$BinDir    = Join-Path $Base 'bin'
$ToolDir   = Join-Path $Base 'uv-tools'
$PyDir     = Join-Path $Base 'python'

$UvVersion = if ($env:VENYA_UV_VERSION) { $env:VENYA_UV_VERSION } else { '0.12.17' }
# Checksum of the PUBLIC uv release artifact, not a credential. detect-secrets
# flags any 64-char hex run; the pragma is the tool's own false-positive marker
# and matches existing repo precedent (tests/e2e/test_rbac_secrets.py).
$UvSha256  = 'a252121d5b59398fcb137c6ea448176459a44010f33f67e0072305a637119ca7'  # pragma: allowlist secret

$tarballUrl = if ($env:VENYA_TARBALL) { $env:VENYA_TARBALL } else {
    'https://github.com/tabith-llc/venya/releases/latest/download/venya-cli-install.tar.gz'
}

Info "Installing Venya CLI machine-wide into $Base"
Info "Administrator: $($identity.Name)"

if ($env:VENYA_SKIP_PROMPT -ne 'yes') {
    $answer = Read-Host "Install venya CLI machine-wide into $Base? [Y/n]"
    if ($answer -match '^[Nn]') { Info 'Aborted.'; exit 0 }
}

$workDir = Join-Path $env:TEMP ("venya-cli-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {
    # --- uv (machine-wide, pinned, sha256-verified) ---
    if ((Test-Path $UvExe) -and ((& $UvExe --version 2>&1) -match [regex]::Escape($UvVersion))) {
        Info "uv $UvVersion already present at $UvExe"
    } else {
        Info "Fetching uv $UvVersion..."
        New-Item -ItemType Directory -Force -Path $UvDir | Out-Null
        $uvZip = Join-Path $workDir 'uv.zip'
        $uvUrl = "https://github.com/astral-sh/uv/releases/download/$UvVersion/uv-x86_64-pc-windows-msvc.zip"
        Invoke-Native -Exe $curl -Arguments @('-fsSL', '-o', $uvZip, $uvUrl) -What "uv download from $uvUrl"

        # Fail-closed, same discipline as the tarball. A pinned hash also replaces
        # the old `Invoke-Expression` of a remote script with a verified binary.
        $uvActual = (Get-FileHash -LiteralPath $uvZip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($uvActual -ne $UvSha256) {
            Fail @"
uv archive SHA-256 mismatch!
  Expected: $UvSha256
  Actual:   $uvActual
Refusing to run an unverified binary. Aborting.
"@
        }
        Info 'uv SHA-256 verified.'
        Invoke-Native -Exe $tar -Arguments @('-xf', $uvZip, '-C', $UvDir) -What 'uv archive extraction'
        Remove-Item -LiteralPath $uvZip -Force
        if (-not (Test-Path $UvExe)) { Fail "uv.exe missing after extraction into $UvDir" }
    }

    # Machine-wide locations, so nothing depends on the installing admin's profile.
    # The uv cache is deliberately TEMPORARY and outside the install root: uv writes
    # its built-wheel cache entries with an explicit protected DACL that names the
    # invoking admin (measured: SYSTEM + Administrators + <admin>, inherited=False).
    # Those files are never read at runtime, so keeping them out of $Base means the
    # delivered tree is entirely inheritance-based, the install does not record who
    # performed it, and ~50 MB is not left behind.
    $CacheDir = Join-Path $workDir 'uv-cache'
    $env:UV_PYTHON_INSTALL_DIR = $PyDir
    $env:UV_TOOL_DIR           = $ToolDir
    $env:UV_TOOL_BIN_DIR       = $BinDir
    $env:UV_CACHE_DIR          = $CacheDir
    New-Item -ItemType Directory -Force -Path $BinDir, $CacheDir | Out-Null

    # --- Download + verify the tarball (pin, else same-origin sidecar; fail-closed) ---
    $tarballFile = Join-Path $workDir 'venya-cli-install.tar.gz'
    Info "Downloading tarball from $tarballUrl..."
    Invoke-Native -Exe $curl -Arguments @('-fsSL', '-o', $tarballFile, $tarballUrl) -What "Download of $tarballUrl"

    $expected = $env:VENYA_TARBALL_SHA256
    if (-not $expected) {
        Info 'VENYA_TARBALL_SHA256 not set - fetching checksum sidecar from origin...'
        $sidecarFile = Join-Path $workDir 'tarball.sha256'
        Invoke-Native -Exe $curl -Arguments @('-fsSL', '-o', $sidecarFile, "$tarballUrl.sha256") -What "Sidecar fetch ${tarballUrl}.sha256 - refusing to install without integrity verification (set VENYA_TARBALL_SHA256 to pin)"
        $line = Get-Content -LiteralPath $sidecarFile -TotalCount 1
        $expected = ($line -split '\s+')[0]
        if (-not $expected) { Fail "Sidecar ${tarballUrl}.sha256 contained no hash. Aborting." }
    }

    Info 'Verifying tarball SHA-256...'
    # Get-FileHash emits uppercase and the sidecar is lowercase; normalise both.
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

    # --- Extract (archive is built with `git archive --prefix=./`: no strip) ---
    $extractDir = Join-Path $workDir 'src'
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Invoke-Native -Exe $tar -Arguments @('xzf', $tarballFile, '-C', $extractDir) -What 'Tarball extraction'
    Remove-Item -LiteralPath $tarballFile -Force

    if (-not (Test-Path (Join-Path $extractDir 'packages\cli\pyproject.toml'))) {
        Fail 'Tarball layout unexpected: packages/cli/pyproject.toml not found.'
    }

    # --- Python + tools ---
    Info 'Installing uv-managed Python 3.14...'
    Invoke-Native -Exe $UvExe -Arguments @('python', 'install', '3.14') -What 'uv python install 3.14'

    # --link-mode copy is LOAD-BEARING. uv defaults to hardlinking wheels out of its
    # cache; a hardlink shares one security descriptor with the cached original,
    # which carries a PROTECTED DACL and no Users ACE, so standard users get
    # PermissionError on import. Measured: 1982 of 4278 files protected in hardlink
    # mode, 0 of 4277 in copy mode. Do not "optimise" this back to the default.
    Info 'Installing venya-cli via uv tool (copy link mode)...'
    Invoke-Native -Exe $UvExe -Arguments @('tool', 'install', '--force', '--python', '3.14', '--link-mode', 'copy', (Join-Path $extractDir 'packages\cli')) -What 'uv tool install venya-cli'

    $installMcp = if ($env:VENYA_INSTALL_MCP) { $env:VENYA_INSTALL_MCP } else { 'yes' }
    if ($installMcp -ne 'no') {
        if (-not (Test-Path (Join-Path $extractDir 'packages\mcp\pyproject.toml'))) {
            Fail 'Tarball layout unexpected: packages/mcp/pyproject.toml not found (VENYA_INSTALL_MCP != no).'
        }
        Info 'Installing venya-mcp via uv tool (copy link mode)...'
        Invoke-Native -Exe $UvExe -Arguments @('tool', 'install', '--force', '--python', '3.14', '--link-mode', 'copy', (Join-Path $extractDir 'packages\mcp')) -What 'uv tool install venya-mcp'
    }

    # --- Regression guard for the hardlink/protected-DACL class ---
    # Cheap enough to always run, and it is the only thing standing between a
    # silent revert to hardlink mode and an install standard users cannot read.
    Info 'Verifying no file was left with a protected DACL...'
    $protected = 0
    Get-ChildItem $Base -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
        $a = Get-Acl -LiteralPath $_.FullName -ErrorAction SilentlyContinue
        if ($a -and $a.AreAccessRulesProtected) { $protected++ }
    }
    if ($protected -gt 0) {
        Fail "$protected file(s) under $Base carry a protected DACL and would be unreadable by standard users. Likely cause: --link-mode copy was dropped. Refusing to leave a broken install."
    }
    Info 'ACL check passed: 0 protected DACLs.'

    # --- Machine PATH (idempotent; never clobbers the existing value) ---
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable('Path', ($machinePath.TrimEnd(';') + ';' + $BinDir), 'Machine')
        Info "Added $BinDir to the MACHINE PATH (effective in new terminals)."
    } else {
        Info "Machine PATH already contains $BinDir"
    }
    $env:Path = "$BinDir;$env:Path"

    # --- Verify ---
    $venyaExe = Join-Path $BinDir 'venya.exe'
    if (-not (Test-Path $venyaExe)) { Fail "venya shim not found at $venyaExe after install." }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $venyaExe --help *> $null
    $helpExit = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($helpExit -ne 0) { Fail "venya --help failed (exit $helpExit)." }
    Info "venya CLI installed: $venyaExe"

    if ($installMcp -ne 'no') {
        $mcpExe = Join-Path $BinDir 'venya-mcp.exe'
        if (-not (Test-Path $mcpExe)) { Fail "venya-mcp shim not found at $mcpExe after install." }
        # No --help probe: venya-mcp is a stdio server and would block. Import check.
        # Windows venvs put the interpreter in Scripts\, not bin/.
        $mcpPython = Join-Path $ToolDir 'venya-mcp\Scripts\python.exe'
        if (Test-Path $mcpPython) {
            Invoke-Native -Exe $mcpPython -Arguments @('-c', 'import venya_mcp.server') -What 'venya-mcp server module import'
        } else {
            Warn "Could not locate the venya-mcp venv interpreter at $mcpPython; skipped the import check."
        }
        Info "venya-mcp installed: $mcpExe"
    }
} finally {
    Remove-Item Env:\UV_PYTHON_INSTALL_DIR, Env:\UV_TOOL_DIR, Env:\UV_TOOL_BIN_DIR, Env:\UV_CACHE_DIR -ErrorAction SilentlyContinue
    if (Test-Path $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- FIDO2 access check ---
# fido2 ships a native Windows HID backend (fido2/hid/windows.py, pure ctypes
# against hid.dll/setupapi.dll), so there is no libusb, no Zadig and no driver
# setup. Administrator rights ARE still needed for the ceremonies, see below.
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

Write-Host ''
Write-Host '============================================'
Write-Host '  Venya CLI installed machine-wide'
Write-Host "  $Base"
Write-Host '============================================'
Write-Host ''
Write-Host 'For EACH operator (standard user, no admin needed to run these):'
Write-Host '  open a NEW terminal so the machine PATH refreshes, then:'
Write-Host '  venya config set-server https://<core-host>'
Write-Host '  curl.exe -sk https://<core-host>/.well-known/venya-ca.crt -o "$env:APPDATA\venya\venya-ca.crt"'
Write-Host '  $env:SSL_CERT_FILE="$env:APPDATA\venya\venya-ca.crt"; venya login <user-id>'
Write-Host ''
Write-Host '  Per-user config/token: %APPDATA%\venya\config.json'
if ($installMcp -ne 'no') {
    Write-Host ''
    Write-Host 'MCP (LLM clients) - point the client at the venya-mcp shim and provide:'
    Write-Host '  VENYA_CONFIG=%APPDATA%\venya\config.json  (server_url + access_token from venya login)'
    Write-Host '  VENYA_CA_CERT=%APPDATA%\venya\venya-ca.crt  (required at startup)'
}
Write-Host ''
