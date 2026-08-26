#!/usr/bin/env python3
"""Generate an enrollment token via DB on venya-core-1.

Runs the token creation logic on the server VM to use the server's
pepper for binding_hash computation. No local dependencies needed.
"""

import os
import subprocess
import sys
import tempfile


_CREATE_SCRIPT = """
import sys, hashlib, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import create_engine, text

pepper = ''
try:
    from server.config import ServerConfig
    pepper = ServerConfig().recovery_code_pepper
except Exception:
    pass

if not pepper:
    sys.exit(1)

hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'venya-enrollment-token-binding-v1')
key = hkdf.derive(pepper.encode())

username = sys.argv[1]
plaintext = sys.argv[2]
msg = f'{username}:{plaintext}'.encode()
binding_hash = hmac.new(key, msg, hashlib.sha256).hexdigest()
token_hash = hashlib.sha256(plaintext.encode()).hexdigest()

engine = create_engine('postgresql://venya:venya808@localhost/venya')
with engine.begin() as conn:
    conn.execute(text('''
        INSERT INTO users (user_id, status, auth_mode, display_name)
        VALUES (:uid, 'pending_enrollment', 'webauthn', :uid)
        ON CONFLICT (user_id) DO UPDATE SET status='pending_enrollment'
    '''), {'uid': username})
    conn.execute(text('''
        INSERT INTO enrollment_tokens (user_id, token_hash, binding_hash, state, created_at, expires_at)
        VALUES (:uid, :th, :bh, 'created', NOW(), NOW() + INTERVAL '15 minutes')
    '''), {'uid': username, 'th': token_hash, 'bh': binding_hash})
print(plaintext)
"""


def generate_token(username="testuser"):
    """Generate enrollment token by running Python on venya-core-1."""
    plaintext = os.urandom(32).hex()

    # Write script to temp file on VM
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(_CREATE_SCRIPT)
        script_path = f.name

    try:
        # Copy script to VM
        subprocess.run(
            ["scp", script_path, "bot@venya-core-1:/tmp/gen_token.py"],
            check=True, capture_output=True, timeout=10,
        )

        # Run on VM
        result = subprocess.run(
            ["ssh", "bot@venya-core-1",
             "echo '' | sudo -S /opt/venya/.venv/bin/python3.14 "
             f"/tmp/gen_token.py {username} {plaintext}"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            print(f"ERROR: {result.stderr}", file=sys.stderr)
            return None

        return result.stdout.strip()
    finally:
        os.unlink(script_path)


if __name__ == "__main__":
    username = sys.argv[1] if len(sys.argv) > 1 else "testuser"
    token = generate_token(username)
    if token:
        print(token)
    else:
        sys.exit(1)
