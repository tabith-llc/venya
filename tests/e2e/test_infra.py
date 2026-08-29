"""Infrastructure E2E tests — VM lifecycle and software install.

Tests the full infrastructure provisioning flow:
1. Destroy existing fleet
2. Provision fresh fleet (DEFAULT: core-1, exec-1, target-1)
3. Build tarballs and start HTTP server
4. Install core on venya-core-1
5. Install executor on venya-exec-1
6. Verify health and connectivity

Runs from montana (10.27.27.35). Requires SSH access to wyoming (hypervisor).
"""

import os
import subprocess

# SSH to wyoming (hypervisor)
WYOMING = "opencode@wyoming"
WYOMING_PROVISION = "/home/opencode/bin/venya-provision-ubuntu.sh"
WYOMING_POWER = "/home/opencode/bin/venya-power-ubuntu.sh"
WYOMING_REMOVE_KNOWN_HOSTS = "/home/opencode/bin/remove_venya_known_hosts.sh"

# Montanan paths
MONTANA_TARBALL_SCRIPT = "/media/dust/dust-ext1/projects/venya-installer/create-tarball-and-serve.sh"
MONTANA_REMOVE_KNOWN_HOSTS = "/home/dust/bin/remove_venya_known_hosts.sh"

# VM access
CORE = "bot@venya-core-1"
EXEC = "bot@venya-exec-1"
TARGET = "bot@venya-target-1"

# Tarball server
TARBALL_SERVER = "http://10.27.27.35:8080"

# Environment variables
CORE_SHA = os.environ.get("VENYA_CORE_SHA256", "")
EXEC_SHA = os.environ.get("VENYA_EXEC_SHA256", "")
DB_PASSWORD = os.environ.get("VENYA_DB_PASSWORD", "venya808")


def _ssh(user_host, cmd, timeout=60):
    """Run a command via SSH."""
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", user_host, cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _ssh_wyoming(cmd, timeout=60):
    """Run a command on wyoming (hypervisor)."""
    return _ssh(WYOMING, cmd, timeout)


def _ssh_montana(cmd, timeout=60):
    """Run a command on montana."""
    return _ssh("dust@montana", cmd, timeout)


class TestInfrastructure:
    """Infrastructure provisioning and installation tests."""

    def test_phase0_destroy_fleet(self):
        """Phase 0: Destroy existing fleet."""
        result = _ssh_wyoming(f"{WYOMING_PROVISION} destroy")
        assert result.returncode == 0, f"Destroy failed: {result.stderr}"
        assert "destroyed" in result.stdout.lower()

    def test_phase1_check_ram(self):
        """Phase 1: Check available RAM on wyoming."""
        result = _ssh_wyoming("free -g")
        assert result.returncode == 0
        # DEFAULT fleet needs 15 GB (3 VMs × 5 GB)
        # Wyoming has 31 GB total; Ollama uses ~half
        assert "31" in result.stdout or "29" in result.stdout or "25" in result.stdout

    def test_phase1_provision_fleet(self):
        """Phase 1: Provision fresh DEFAULT fleet."""
        result = _ssh_wyoming(WYOMING_PROVISION)
        assert result.returncode == 0, f"Provision failed: {result.stderr}"
        assert "venya-core-1" in result.stdout
        assert "venya-exec-1" in result.stdout
        assert "venya-target-1" in result.stdout

    def test_phase1_power_on_and_ssh(self):
        """Phase 1: Power on fleet and verify SSH."""
        result = _ssh_wyoming(f"{WYOMING_POWER} start")
        assert result.returncode == 0, f"Power on failed: {result.stderr}"

        # Verify SSH to each VM
        for vm in [CORE, EXEC, TARGET]:
            result = _ssh(vm, "uname -r && hostname")
            assert result.returncode == 0, f"SSH to {vm} failed: {result.stderr}"
            assert "venya" in result.stdout.lower()

    def test_phase1_clean_known_hosts(self):
        """Phase 1: Clean stale host keys on montana and wyoming."""
        result = _ssh_montana(MONTANA_REMOVE_KNOWN_HOSTS)
        assert result.returncode == 0, f"Montana known_hosts cleanup failed: {result.stderr}"

        result = _ssh_wyoming(WYOMING_REMOVE_KNOWN_HOSTS)
        assert result.returncode == 0, f"Wyoming known_hosts cleanup failed: {result.stderr}"

    def test_phase1_outbound_internet(self):
        """Phase 1: Verify outbound internet from venya-core-1."""
        result = _ssh(CORE, "curl -sI https://archive.ubuntu.com | head -1")
        assert result.returncode == 0
        assert "200" in result.stdout

    def test_phase1_build_tarballs(self):
        """Phase 1: Build tarballs and start HTTP server."""
        result = _ssh_montana(MONTANA_TARBALL_SCRIPT)
        assert result.returncode == 0, f"Tarball build failed: {result.stderr}"
        assert "tarball created" in result.stdout.lower()

        # Verify tarball server is running
        result = _ssh_montana(f"curl -fsI {TARBALL_SERVER}/install-venya-core.sh | head -1")
        assert result.returncode == 0
        assert "200" in result.stdout

        # Extract SHA256 hashes for later use
        core_sha_result = _ssh_montana(
            f"cat {MONTANA_TARBALL_SCRIPT.replace('create-tarball-and-serve.sh', '')}venya-core-install.tar.gz.sha256 2>/dev/null || cat /media/dust/dust-ext1/projects/venya-installer/venya-core-install.tar.gz.sha256"
        )
        if core_sha_result.returncode == 0:
            global CORE_SHA
            CORE_SHA = core_sha_result.stdout.strip().split()[0]

        exec_sha_result = _ssh_montana(
            "cat /media/dust/dust-ext1/projects/venya-installer/venya-executor-install.tar.gz.sha256"
        )
        if exec_sha_result.returncode == 0:
            global EXEC_SHA
            EXEC_SHA = exec_sha_result.stdout.strip().split()[0]

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
        result = _ssh_montana(
            f'curl -sk {TARBALL_SERVER.replace("10.27.27.35", "venya-core-1").replace("http", "https").replace(":8080", "")}/api/v1/health'
        )
        assert result.returncode == 0
        assert '"status":"ok"' in result.stdout or '"status": "ok"' in result.stdout

    def test_phase2_db_migrated(self):
        """Phase 2: Verify DB migrated from scratch."""
        result = _ssh(CORE, 'sudo -u postgres psql -d venya -t -A -c "SELECT version_num FROM alembic_version;"')
        assert result.returncode == 0
        assert result.stdout.strip()  # Should have a version number

    def test_phase2_python_version(self):
        """Phase 2: Verify runtime is Python 3.14."""
        result = _ssh(CORE, "/opt/venya/.venv/bin/python3 --version")
        assert result.returncode == 0
        assert "3.14" in result.stdout

    def test_phase2_admin_mtls_assets(self):
        """Phase 2: Verify admin mTLS assets exist."""
        result = _ssh(CORE, "ls -la /etc/venya/admin/admin.crt /etc/venya/admin/admin.key")
        assert result.returncode == 0

    def test_phase2_admin_mtls_positive(self):
        """Phase 2: Positive admin mTLS test."""
        result = _ssh_montana(
            "curl -sk --cacert /var/lib/venya/admin-ca/admin-ca.crt "
            "--cert /etc/venya/admin/admin.crt "
            "--key /etc/venya/admin/admin.key "
            "https://venya-core-1/api/v1/admin/users"
        )
        assert result.returncode == 0
        assert "200" in result.stdout or '"users"' in result.stdout

    def test_phase2_admin_mtls_negative(self):
        """Phase 2: Negative admin mTLS test (no cert)."""
        result = _ssh_montana(
            "curl -sk --cacert /var/lib/venya/admin-ca/admin-ca.crt " "https://venya-core-1/api/v1/admin/users"
        )
        assert result.returncode == 0
        # Should be rejected (403 or similar)
        assert "403" in result.stdout or "401" in result.stdout or "Admin access requires" in result.stdout

    def test_phase3_executor_install(self):
        """Phase 3: Install executor on venya-exec-1."""
        assert EXEC_SHA, "EXEC_SHA not set — run test_phase1_build_tarballs first"

        # First, get an enrollment token via DB (for automated testing)
        # In production, this would use FIDO2-authenticated CLI
        result = _ssh(
            CORE,
            "sudo -u postgres psql -d venya -c \"UPDATE users SET status='active', auth_mode='mTLS' WHERE user_id='exec-1';\"",
        )
        assert result.returncode == 0

        result = _ssh(
            EXEC,
            f"curl -fsSL {TARBALL_SERVER}/install-venya-executor.sh | "
            f"sudo VENYA_SKIP_PROMPT=yes "
            f"VENYA_EXECUTOR_ID=exec-1 "
            f"VENYA_SERVER_URL=https://venya-core-1 "
            f"VENYA_TARBALL_SHA256={EXEC_SHA} "
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
        result = _ssh(
            CORE,
            "sudo -u postgres psql -d venya -t -A -c \"SELECT user_id, status FROM users WHERE user_id='exec-1';\"",
        )
        assert result.returncode == 0
        assert "exec-1" in result.stdout
        assert "active" in result.stdout
