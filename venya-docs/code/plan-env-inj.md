# .env Secrets Injector Design

**Status:** Proposed
**Date:** 2025-08-04

---

## Problem Statement

LLM agents executing shell commands via the Venya executor can accidentally leak secrets:

1. **`/proc/<pid>/environ`** — any process can read its own environment variables
2. **`printenv` / `env`** — shell builtins that dump all env vars
3. **`os.environ`** — Python's `os.environ` exposes all env vars
4. **Logging frameworks** — may inadvertently log env vars in debug output
5. **Core dumps** — process memory (including env) written to disk on crash
6. **Container inspection** — `docker exec` or `nsenter` can read procfs

An LLM that receives a secret like `API_KEY=sk-abc123` as an env var can trivially exfiltrate it by running `printenv` or reading `/proc/self/environ`.

---

## Goal

Provide a mechanism to inject secrets as shell `.env` variables in a way that:

- Secrets are **not visible** in `/proc/<pid>/environ`
- Secrets are **not visible** to `printenv`, `env`, or `os.environ`
- Secrets are **not visible** in process command lines
- Secrets are **available** to the target command via a secure read mechanism
- Secrets are **automatically cleaned up** after command completion
- The mechanism integrates with the existing Venya vault and executor pipeline

---

## Design Options

### Option A: memfd + execve() Injection (Recommended)

**Concept:** Inject secrets via `memfd` file descriptors during `execve()`, bypassing the environment entirely. The target process reads secrets from the FDs.

**How it works:**

```
1. Executor fetches secrets from vault (wrapped with sentinels)
2. For each secret, create a memfd containing the secret value
3. Set FD numbers as known constants (e.g., 100-199)
4. Call execve() with the secret FDs open (not via env vars)
5. Target process reads from known FD numbers
6. After execve(), executor closes FDs and zeroes memory
```

**Advantages:**
- Secrets never appear in `/proc/<pid>/environ`
- Secrets never appear in command line arguments
- Secrets not in process memory after close()
- Works with any binary (no wrapper needed)

**Disadvantages:**
- Target process must know how to read from specific FDs
- Requires a small wrapper library or convention

**Implementation:**
```python
# In executor.py _run_command():
import os
import tempfile

SECRET_BASE_FD = 100  # Start injecting at FD 100

def inject_env_via_memfd(command: str, env_secrets: dict[str, bytes]) -> tuple[subprocess.Popen, list[int]]:
    """Inject secrets via memfd, not environment variables.
    
    Returns:
        (process, list_of_closed_fds)
    """
    open_fds = []
    env = os.environ.copy()  # No VENYA_* vars!
    
    for i, (key, value) in enumerate(env_secrets.items()):
        fd = memfd_create(f"venya_secret_{i}", MFD_CLOEXEC)
        os.write(fd, value)
        os.lseek(fd, 0, SEEK_SET)
        open_fds.append(fd)
    
    # Set a single "pointer" env var with FD count
    env["VENYA_SECRET_COUNT"] = str(len(open_fds))
    
    process = subprocess.Popen(
        command,
        shell=True,
        env=env,
        pass_fds=open_fds,  # Only pass these FDs, not all open fds
    )
    
    # Close our copies immediately
    for fd in open_fds:
        os.close(fd)
    
    return process, open_fds
```

**Target process convention:**
```bash
#!/bin/bash
# The target wrapper reads secrets from known FDs
read_secret() {
    local fd=$((100 + $1))
    cat <&$fd
}

API_KEY=$(read_secret 0)    # First secret
DB_PASSWORD=$(read_secret 1) # Second secret

# Now run the actual command with secrets in shell variables
# These are shell-local, not process-env
exec_command_with_secrets "$API_KEY" "$DB_PASSWORD"
```

---

### Option B: seccomp-bpf Sandboxing

**Concept:** Apply a seccomp filter that blocks reads from `/proc/<pid>/environ` and blocks `printenv`-like syscalls.

**How it works:**

```python
import seccomp
from seccomp import Syscall, Cond, Action, Rule

def apply_env_sandbox(pid: int):
    """Block /proc/self/environ reads and printenv syscalls."""
    ctx = seccomp.SyscallFilter(Action.KILL)
    
    # Block open/read of /proc/self/environ
    ctx.add_rule(Rule(Syscall.OPENAT, Cond.EQ, "/proc/self/environ", Action.KILL))
    
    # Block getdents/getdents64 on /proc/<pid>/fd/
    ctx.load()
```

**Advantages:**
- Transparent to target process
- No wrapper needed
- Defense-in-depth (works even if memfd leaks)

**Disadvantages:**
- Complex to get right (may break legitimate /proc usage)
- Only protects the specific process, not child processes
- seccomp not available on all platforms
- Can be bypassed with ptrace or LD_PRELOAD

---

### Option C: Named Pipe (FIFO) Injection

**Concept:** Create named pipes for each secret. The target process opens and reads from the pipe. Pipes are one-read, auto-closing.

**How it works:**

```python
import os
import tempfile

def inject_via_fifo(command: str, env_secrets: dict[str, bytes]) -> subprocess.Popen:
    """Inject secrets via named pipes in a tmpfs directory."""
    fifo_dir = tempfile.mkdtemp(prefix="venya_fifo_")
    
    pipe_paths = {}
    for i, (key, value) in enumerate(env_secrets.items()):
        pipe_path = os.path.join(fifo_dir, f"secret_{i}")
        os.mkfifo(pipe_path)
        
        # Write secret in background thread
        def write_secret(path, data):
            with open(path, 'wb') as f:
                f.write(data)
        threading.Thread(target=write_secret, args=(pipe_path, value), daemon=True).start()
        
        pipe_paths[key] = pipe_path
    
    # Pass pipe paths via a single env var (not the secrets themselves)
    env = os.environ.copy()
    env["VENYA_PIPE_DIR"] = fifo_dir
    env["VENYA_PIPE_COUNT"] = str(len(pipe_paths))
    
    process = subprocess.Popen(command, shell=True, env=env)
    
    # Clean up after process exits
    process.wait()
    shutil.rmtree(fifo_dir, ignore_errors=True)
    
    return process
```

**Advantages:**
- Simple to implement
- One-read semantics (pipe closes after first read)
- No special wrapper needed (just read the pipe)

**Disadvantages:**
- Secrets exist on disk briefly (even on tmpfs)
- Race condition: pipe must be opened before write completes
- FIFO path visible in VENYA_PIPE_DIR env var
- Not as secure as memfd

---

### Option D: Process Substitution + Here-String

**Concept:** Use shell process substitution to inject secrets without env vars.

**How it works:**

```bash
# Instead of: API_KEY=secret command
# Use:
command <(cat /dev/fd/3) 3< <(echo "secret_value")
```

Or via a wrapper script:

```bash
#!/bin/bash
# venya-env-wrapper
# Reads secrets from stdin, one per line, with null separators

read -r -d '' API_KEY <&3
read -r -d '' DB_PASSWORD <&4

# Export to shell-local variables (not process env)
# Use eval to set them in the current shell context
eval "export $1=$API_KEY"
eval "export $2=$DB_PASSWORD"

exec "$@"
```

**Advantages:**
- No external dependencies
- Works with any shell command

**Disadvantages:**
- Requires wrapper script
- Secrets may appear in shell history or logs
- Limited to shell commands (not binaries)

---

## Recommended Approach: Option A (memfd) + Option B (seccomp)

Combine memfd injection with optional seccomp sandboxing for defense-in-depth:

```
┌─────────────────────────────────────────────────────────────┐
│                     Venya Executor                          │
│                                                             │
│  1. Fetch secrets from vault (encrypted)                    │
│  2. Create memfd for each secret                            │
│  3. Apply seccomp filter (optional, configurable)           │
│  4. execve() with FDs open, no env vars                     │
│  5. Close FDs immediately                                   │
│  6. Zero secret memory                                      │
│  7. Wait for command completion                             │
│  8. Apply cleanup (delete temp files, revoke tokens)        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Target Process                           │
│                                                             │
│  /proc/self/environ     → NO secrets visible                │
│  printenv               → NO secrets visible                │
│  os.environ             → NO secrets visible                │
│  /proc/self/fd/100-199  → Secret values (readable)         │
│  Command args           → NO secrets visible                │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: memfd Injection Core

**Files to modify:**
- `packages/executor/src/venya_executor/injector.py` — Add `inject_via_memfd_fdpass()`
- `packages/executor/src/venya_executor/executor.py` — Update `_run_command()` to use memfd injection
- `packages/executor/src/rust/` — Add Rust-side memfd creation for cross-language support

**New functions:**
```python
def create_secret_memfd(name: str, value: bytes) -> int:
    """Create a memfd containing a secret value with CLOEXEC."""
    import os
    import ctypes
    
    LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    
    # memfd_create(name, flags)
    MFD_CLOEXEC = 0x0001
    fd = LIBC.memfd_create(name.encode(), MFD_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "memfd_create failed")
    
    os.write(fd, value)
    os.lseek(fd, 0, SEEK_SET)
    return fd

def pass_fds_to_process(command: str, secrets: dict[str, bytes], base_fd: int = 100):
    """Create memfds and pass them to a subprocess."""
    fds = []
    for i, (key, value) in enumerate(secrets.items()):
        fd = create_secret_memfd(f"venya_secret_{key}", value)
        fds.append(fd)
    
    # Build env without secrets
    env = os.environ.copy()
    env["_VENYA_SECRET_COUNT"] = str(len(fds))
    env["_VENYA_SECRET_BASE_FD"] = str(base_fd)
    
    process = subprocess.Popen(
        command,
        shell=True,
        env=env,
        pass_fds=fds,
    )
    
    # Close our copies
    for fd in fds:
        os.close(fd)
    
    return process
```

### Phase 2: Shell Wrapper Convention

**Create a small shell wrapper** that target commands can use:

```bash
# venya-env-read.sh
#!/bin/bash
# Read secrets from memfd file descriptors
# Usage: source venya-env-read.sh
#   Then access: $VENYA_SECRET_0, $VENYA_SECRET_1, etc.

_venya_secret_count="${_VENYA_SECRET_COUNT:-0}"
_venya_secret_base_fd="${_VENYA_SECRET_BASE_FD:-100}"

for i in $(seq 0 $((_venya_secret_count - 1))); do
    fd=$((_venya_secret_base_fd + i))
    eval "VENYA_SECRET_$i=\"$(cat <&$fd)\""
done

# Unset the helper vars
unset _VENYA_SECRET_COUNT _VENYA_SECRET_BASE_FD
```

### Phase 3: seccomp Sandbox (Optional)

**Create an optional seccomp filter:**

```python
# packages/executor/src/venya_executor/sandbox.py
try:
    import seccomp
    SECCOMP_AVAILABLE = True
except ImportError:
    SECCOMP_AVAILABLE = False

def apply_env_sandbox(pid: int):
    """Apply seccomp filter to block /proc/self/environ reads."""
    if not SECCOMP_AVAILABLE:
        return
    
    ctx = seccomp.SyscallFilter(seccomp.Action.KILL)
    
    # Block openat on /proc/<pid>/environ
    ctx.add_rule(seccomp.Syscall.OPENAT, seccomp.Cond.EQ, "/proc/self/environ", seccomp.Action.KILL)
    
    # Block read on /proc/self/environ
    ctx.load()
```

### Phase 4: Integration Tests

**Create `packages/executor/tests/test_memfd_injection.py`:**

```python
def test_memfd_not_in_environ():
    """Verify secrets are not in /proc/self/environ."""
    process = pass_fds_to_process(
        "cat /proc/self/environ | grep -c API_KEY || true",
        {"API_KEY": b"secret-value-123"}
    )
    stdout, _ = process.communicate()
    assert stdout.strip() == b"0"

def test_memfd_readable():
    """Verify secrets are readable from the memfd."""
    process = pass_fds_to_process(
        "cat <&100",
        {"API_KEY": b"secret-value-123"}
    )
    stdout, _ = process.communicate()
    assert stdout == b"secret-value-123"

def test_memfd_not_in_printenv():
    """Verify secrets are not in printenv output."""
    process = pass_fds_to_process(
        "printenv | grep -c API_KEY || true",
        {"API_KEY": b"secret-value-123"}
    )
    stdout, _ = process.communicate()
    assert stdout.strip() == b"0"
```

---

## Security Analysis

### Threat Model

| Attack Vector | memfd injection | seccomp sandbox | Both |
|--------------|-----------------|-----------------|------|
| `/proc/<pid>/environ` read | Blocked | Blocked | Blocked |
| `printenv` / `env` | Blocked | Blocked | Blocked |
| `os.environ` (Python) | Blocked | Blocked | Blocked |
| Core dump | Partially protected | Blocked | Blocked |
| `strace` | Visible in trace | Blocked | Blocked |
| `/proc/<pid>/fd/` listing | FDs visible, content not | Blocked | Blocked |
| LD_PRELOAD attack | Vulnerable | Vulnerable | Vulnerable |
| ptrace attach | Vulnerable | Blocked | Blocked |

### Limitations

1. **Trust boundary:** The executor process itself is trusted. If the executor is compromised, secrets can be read before injection.
2. **Child processes:** Child processes inherit the memfd FDs. They must not leak them.
3. **LD_PRELOAD:** An attacker can preload a library that reads /proc/self/environ before the sandbox loads.
4. **Debuggers:** `gdb` or `strace` can read process memory.

### Mitigations

1. **CLOEXEC:** memfds are created with `MFD_CLOEXEC`, so FDs close on exec() unless explicitly passed.
2. **Immediate close:** Executor closes FD copies immediately after `pass_fds`, so only the child has them.
3. **Zero on close:** The executor zeroes secret memory after closing all FDs.
4. **seccomp:** Optional sandbox blocks /proc reads for defense-in-depth.
5. **Audit logging:** All secret accesses are logged via the audit system.

---

## Comparison with Existing Mechanisms

| Mechanism | Visible in `/proc/environ` | Visible in `printenv` | Requires Wrapper | Cross-Platform |
|-----------|---------------------------|----------------------|------------------|----------------|
| Environment variables | Yes | Yes | No | Yes |
| Command line args | Yes | No | No | Yes |
| File on disk | No | No | No | Yes |
| memfd (this proposal) | No | No | Optional | Linux only |
| Named pipe (FIFO) | No | No | No | Yes |
| Unix domain socket | No | No | Yes | Yes |

---

## Integration with Existing Venya Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User / LLM                               │
│                         "run: python train.py"                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     venya exec CLI                              │
│  1. Authenticate (WebAuthn)                                     │
│  2. Fetch secrets from vault: /secrets/{key}/executor           │
│  3. Create session: POST /executors/sessions                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Executor Daemon                               │
│  1. Retrieve secret bundles (sentinel-wrapped)                  │
│  2. Create memfds for each secret value                         │
│  3. Apply seccomp sandbox (if configured)                       │
│  4. execve() with memfd FDs, no env vars                        │
│  5. Close FDs, zero memory                                      │
│  6. Wait for command, capture output                            │
│  7. Send output to server filter (Stage 2)                      │
│  8. Revoke secret tokens                                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Server (Stage 2 Filter)                       │
│  1. Receive captured stdout/stderr                              │
│  2. Hash-match against secret values                            │
│  3. Mask any leaked secrets                                     │
│  4. Return sanitized output                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration

Add to `venya.toml`:

```toml
[executor]
# Injection method: "env" (current), "memfd" (recommended), "fifo"
injection_method = "memfd"

# Apply seccomp sandbox (Linux only)
sandbox_seccomp = true

# Base FD for memfd injection (100-199 reserved)
secret_base_fd = 100

# Zero secret memory after use (always true for memfd)
zero_on_close = true
```

---

## Future Enhancements

1. **Per-command injection policies:** Allow admins to specify which secrets can be injected via which methods.
2. **Secret rotation during execution:** For long-running processes, rotate secrets mid-execution.
3. **Hardware-backed secrets:** Use TPM or Intel SGX for secret storage and injection.
4. **Secret expiration:** Auto-expire secrets after a configurable time window.
5. **Secret usage auditing:** Log which commands accessed which secrets.
6. **Cross-platform support:** Windows named pipes, macOS Mach ports.
