# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Infrastructure E2E tests — VM lifecycle and software install.

Tests the full infrastructure provisioning flow:
1. Destroy existing fleet
2. Provision fresh fleet (DEFAULT: core-1, exec-1, target-1)
3. Build tarballs and start HTTP server
4. Install core on venya-core-1
5. Install executor on venya-exec-1
6. Verify health and connectivity

Runs from the operator workstation; requires SSH access to the hypervisor
host. ALL lab coordinates come from VENYA_TEST_* environment variables —
this file ships in published release tarballs, so it carries NO hardcoded
private infrastructure (ticket strip-private-infra-from-published-tree).
"""

import os
import subprocess
import time
from pathlib import Path

import pytest


def _require_env(name: str, example: str) -> str:
    """Lab coordinate with NO built-in default — the module skips loudly when
    the operator's environment is not configured (published-file discipline:
    private infrastructure identifiers must never be hardcoded here)."""
    value = os.environ.get(name)
    if not value:
        pytest.skip(
            f"{name} not set (example: {example}) — the infra E2E harness " "requires the operator's lab environment",
            allow_module_level=True,
        )
    return value


# SSH to the hypervisor host + its VM-management scripts
HYPERVISOR = _require_env("VENYA_TEST_HYPERVISOR", "user@hypervisor-host")
HYPERVISOR_PROVISION = _require_env("VENYA_TEST_PROVISION_SCRIPT", "/path/to/venya-provision-ubuntu.sh")
HYPERVISOR_POWER = _require_env("VENYA_TEST_POWER_SCRIPT", "/path/to/venya-power-ubuntu.sh")
HYPERVISOR_REMOVE_KNOWN_HOSTS = _require_env(
    "VENYA_TEST_HYPERVISOR_KNOWN_HOSTS_SCRIPT", "/path/to/remove_known_hosts.sh"
)

# Operator-workstation coordinates (the harness runs ON the workstation)
WORKSTATION_SSH = _require_env("VENYA_TEST_WORKSTATION_SSH", "user@workstation")
WORKSTATION_TARBALL_SCRIPT = _require_env("VENYA_TEST_TARBALL_SCRIPT", "/path/to/create-tarball-and-serve.sh")
WORKSTATION_REMOVE_KNOWN_HOSTS = _require_env("VENYA_TEST_REMOVE_KNOWN_HOSTS_SCRIPT", "/path/to/remove_known_hosts.sh")

# VM access (fleet naming convention per docs/full-lifecycle-test.md)
CORE = os.environ.get("VENYA_TEST_CORE_SSH", "bot@venya-core-1")
EXEC = os.environ.get("VENYA_TEST_EXEC_SSH", "bot@venya-exec-1")
TARGET = os.environ.get("VENYA_TEST_TARGET_SSH", "bot@venya-target-1")

# Build-mirror server serving the tag-built tarballs + its sidecar directory
TARBALL_SERVER = _require_env("VENYA_TEST_TARBALL_SERVER", "http://<build-host>:8080")
SIDECAR_DIR = _require_env("VENYA_TEST_SIDECAR_DIR", "/path/to/venya-installer")

# Environment variables
CORE_SHA = os.environ.get("VENYA_CORE_SHA256", "")
EXEC_SHA = os.environ.get("VENYA_EXEC_SHA256", "")
DB_PASSWORD = _require_env("VENYA_DB_PASSWORD", "the lab installer's DB password")


def _ssh(user_host, cmd, timeout=60):
    """Run a command via SSH."""
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", user_host, cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _ssh_hypervisor(cmd, timeout=60):
    """Run a command on the hypervisor host."""
    return _ssh(HYPERVISOR, cmd, timeout)


def _ssh_workstation(cmd, timeout=60):
    """Run a command on the operator workstation."""
    return _ssh(WORKSTATION_SSH, cmd, timeout)


class TestInfrastructure:
    """Infrastructure provisioning and installation tests."""

    def test_phase0_destroy_fleet(self):
        """Phase 0: Destroy existing fleet."""
        result = _ssh_hypervisor(f"{HYPERVISOR_PROVISION} destroy")
        assert result.returncode == 0, f"Destroy failed: {result.stderr}"
        assert "destroyed" in result.stdout.lower()

    def test_phase1_check_ram(self):
        """Phase 1: Check available RAM on the hypervisor."""
        result = _ssh_hypervisor("free -g")
        assert result.returncode == 0
        # DEFAULT fleet needs 15 GB (3 VMs × 5 GB)
        total_g = int(result.stdout.splitlines()[1].split()[1])
        assert total_g >= 15, f"hypervisor total RAM {total_g}G < 15G needed for the default fleet"

    def test_phase1_provision_fleet(self):
        """Phase 1: Provision fresh DEFAULT fleet."""
        result = _ssh_hypervisor(HYPERVISOR_PROVISION)
        assert result.returncode == 0, f"Provision failed: {result.stderr}"
        assert "venya-core-1" in result.stdout
        assert "venya-exec-1" in result.stdout
        assert "venya-target-1" in result.stdout

    def test_phase1_power_on_and_ssh(self):
        """Phase 1: Power on fleet and verify SSH."""
        result = _ssh_hypervisor(f"{HYPERVISOR_POWER} boot")
        assert result.returncode == 0, f"Power on failed: {result.stderr}"

        # Verify SSH to each VM
        for vm in [CORE, EXEC, TARGET]:
            result = _ssh(vm, "uname -r && hostname")
            assert result.returncode == 0, f"SSH to {vm} failed: {result.stderr}"
            assert "venya" in result.stdout.lower()

    def test_phase1_clean_known_hosts(self):
        """Phase 1: Clean stale host keys on the workstation and hypervisor."""
        # On the workstation, run locally (can't SSH to self)
        result = subprocess.run(
            [WORKSTATION_REMOVE_KNOWN_HOSTS],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        # Script may exit 0 or 1 (no hosts to clean) — both OK
        assert "known_hosts" in result.stdout.lower() or result.returncode in (0, 1)

        result = _ssh_hypervisor(HYPERVISOR_REMOVE_KNOWN_HOSTS)
        assert result.returncode == 0, f"Hypervisor known_hosts cleanup failed: {result.stderr}"

    def test_phase1_outbound_internet(self):
        """Phase 1: Verify outbound internet from venya-core-1."""
        result = _ssh(CORE, "curl -sI https://archive.ubuntu.com | head -1")
        assert result.returncode == 0
        assert "200" in result.stdout

    def test_phase1_build_tarballs(self):
        """Phase 1: Build tarballs and start HTTP server."""
        result = subprocess.run(
            [WORKSTATION_TARBALL_SCRIPT],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, f"Tarball build failed: {result.stderr}"
        assert "tarball created" in result.stdout.lower()

        # Verify tarball server is running
        result = subprocess.run(
            ["curl", "-fsI", f"{TARBALL_SERVER}/install-venya-core.sh"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0
        assert "200" in result.stdout

        # Extract SHA256 hashes for later use (fail loudly if the build phase
        # did not produce sidecars — no hardcoded fallbacks in a published file)
        global CORE_SHA
        with open(f"{SIDECAR_DIR}/venya-core-install.tar.gz.sha256") as f:
            CORE_SHA = f.read().strip().split()[0]

        global EXEC_SHA
        with open(f"{SIDECAR_DIR}/venya-executor-install.tar.gz.sha256") as f:
            EXEC_SHA = f.read().strip().split()[0]

    def test_phase2_install_core(self):
        """Phase 2: Install core on venya-core-1."""
        assert CORE_SHA, "CORE_SHA not set — run test_phase1_build_tarballs first"

        result = _ssh(
            CORE,
            f"curl -fsSL {TARBALL_SERVER}/install-venya-core.sh | "
            f"sudo VENYA_SKIP_PROMPT=yes "
            f"VENYA_DB_PASSWORD={DB_PASSWORD} "
            f"VENYA_TARBALL_SHA256={CORE_SHA} "
            f"bash -s 2>&1",
            timeout=300,
        )
        assert result.returncode == 0, f"Core install failed: {result.stderr}"
        assert "Installation verified" in result.stdout

    def test_phase2_core_health(self):
        """Phase 2: Verify core health."""
        # Retry loop — Nginx may return 502 before backend is ready
        for attempt in range(6):
            result = subprocess.run(
                ["curl", "-sk", "https://venya-core-1/api/v1/health"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and ('"status":"ok"' in result.stdout or '"status": "ok"' in result.stdout):
                break
            time.sleep(5)
        assert result.returncode == 0
        assert '"status":"ok"' in result.stdout or '"status": "ok"' in result.stdout

    def test_phase2_db_migrated(self):
        """Phase 2: Verify DB migrated from scratch."""
        result = _ssh(CORE, 'sudo -u postgres psql -d venya -t -A -c "SELECT version_num FROM alembic_version;"')
        assert result.returncode == 0
        assert result.stdout.strip()  # Should have a version number

    def test_phase2_python_version(self):
        """Phase 2: Verify runtime is Python 3.14."""
        # Clean stale known_hosts (VMs may have been recreated)
        subprocess.run(
            ["ssh-keygen", "-f", str(Path.home() / ".ssh" / "known_hosts"), "-R", "venya-core-1"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        result = _ssh(CORE, "/opt/venya/.venv/bin/python3 --version")
        assert result.returncode == 0
        assert "3.14" in result.stdout

    def test_phase2_admin_mtls_assets(self):
        """Phase 2: Verify admin mTLS assets exist."""
        result = _ssh(CORE, "sudo ls -la /etc/venya/admin/admin.crt /etc/venya/admin/admin.key")
        assert result.returncode == 0

    def test_phase2_admin_mtls_positive(self):
        """Phase 2: Positive admin mTLS test."""
        result = _ssh(
            CORE,
            "sudo curl -sk --cacert /var/lib/venya/admin-ca/admin-ca.crt "
            "--cert /etc/venya/admin/admin.crt "
            "--key /etc/venya/admin/admin.key "
            "https://localhost/api/v1/admin/users",
        )
        assert result.returncode == 0
        assert "200" in result.stdout or '"users"' in result.stdout

    def test_phase2_admin_mtls_negative(self):
        """Phase 2: Negative admin mTLS test (no cert)."""
        result = subprocess.run(
            [
                "curl",
                "-sk",
                "--cacert",
                "/var/lib/venya/admin-ca/admin-ca.crt",
                "https://venya-core-1/api/v1/admin/users",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0
        # Should be rejected (403 or similar)
        assert "403" in result.stdout or "401" in result.stdout or "Admin access requires" in result.stdout

    def test_phase3_executor_install(self):
        """Phase 3: Install executor on venya-exec-1."""
        assert EXEC_SHA, "EXEC_SHA not set — run test_phase1_build_tarballs first"

        # Generate a valid enrollment token for automated testing
        token = _generate_executor_enrollment_token("exec-1")
        assert token, "Failed to generate executor enrollment token"

        result = _ssh(
            EXEC,
            f"curl -fsSL {TARBALL_SERVER}/install-venya-executor.sh | "
            f"sudo VENYA_SKIP_PROMPT=yes "
            f"VENYA_EXECUTOR_ID=exec-1 "
            f"VENYA_SERVER_URL=https://venya-core-1 "
            f"VENYA_TARBALL_SHA256={EXEC_SHA} "
            f"VENYA_EXECUTOR_ENROLLMENT_TOKEN={token} "
            f"bash -s 2>&1",
            timeout=300,
        )
        assert result.returncode == 0, f"Executor install failed: {result.stderr}"
        assert "Installation verified" in result.stdout

    def test_phase3_executor_online(self):
        """Phase 3: Verify executor is online."""
        result = _ssh(EXEC, "sudo systemctl is-active venya-executor")
        assert result.returncode == 0
        assert "active" in result.stdout

    def test_phase3_executor_registered(self):
        """Phase 3: Verify executor is registered on core."""
        # Check that the enrollment token was consumed (indicates successful registration)
        result = _ssh(
            CORE,
            "sudo -u postgres psql -d venya -t -A -c \"SELECT state FROM executor_enrollment_tokens WHERE executor_id='exec-1' ORDER BY created_at DESC LIMIT 1;\"",
        )
        assert result.returncode == 0
        assert "consumed" in result.stdout


def _generate_executor_enrollment_token(executor_id):
    """Generate a valid executor enrollment token for automated testing.

    Uses the server's pepper to compute a valid token_hash, then inserts
    it into the executor_enrollment_tokens table. Returns the plaintext token.

    This is test-only code — it does not modify production code.
    """

    plaintext = os.urandom(32).hex()

    # Generate token_hash on the server using the server's pepper
    _GEN_SCRIPT = """
import sys, hmac, hashlib
from sqlalchemy import create_engine, text

pepper = ''
try:
    from server.config import ServerConfig
    pepper = ServerConfig().recovery_code_pepper
except Exception:
    pass

if not pepper:
    sys.exit(1)

executor_id = sys.argv[1]
plaintext = sys.argv[2]
token_hash = hmac.new(pepper.encode(), plaintext.encode(), hashlib.sha256).hexdigest()

engine = create_engine('__DB_URL__')
with engine.begin() as conn:
    conn.execute(text('''
        INSERT INTO executor_enrollment_tokens (executor_id, token_hash, state, created_at, expires_at, created_by)
        VALUES (:eid, :th, 'created', NOW(), NOW() + INTERVAL '15 minutes', 'e2e-test')
        ON CONFLICT (token_hash) DO NOTHING
    '''), {'eid': executor_id, 'th': token_hash})
print(plaintext)
"""

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        db_url = os.environ.get("VENYA_TEST_DB_URL")
        if not db_url:
            raise RuntimeError(
                "VENYA_TEST_DB_URL not set (example: postgresql://venya:<password>@localhost/venya, "
                "evaluated ON the core VM) — no hardcoded default in a published file"
            )
        f.write(_GEN_SCRIPT.replace("__DB_URL__", db_url))
        script_path = f.name

    try:
        subprocess.run(
            ["scp", script_path, f"{CORE}:/tmp/gen_exec_token.py"],
            check=True,
            capture_output=True,
            timeout=10,
        )

        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                CORE,
                (
                    "echo '' | sudo -S /opt/venya/.venv/bin/python3.14 "
                    f"/tmp/gen_exec_token.py {executor_id} {plaintext}"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            return None

        return result.stdout.strip()
    finally:
        os.unlink(script_path)
