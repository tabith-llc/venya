# Certificate Rotation Runbook

Procedures for managing executor mTLS certificates and CA key rotation.

## Prerequisites

- Access to the Vault Server (as `venya-vault` user or admin)
- `venya` CLI installed and configured
- Access to executor machines (for CA cert distribution)

---

## 1. Normal Certificate Rotation (Executor Self-Rotation)

Executors automatically rotate their certificates every 30 days (configurable via `executor.certificate_rotation_days`).

**No admin action required.** The executor:
1. Detects cert expiry within `rotate_before_days` (default: 3 days)
2. Generates a new keypair + CSR
3. Submits CSR to `POST /api/v1/executors/register`
4. Receives and installs the new certificate

**Verify rotation succeeded:**
```bash
# Check executor logs
sudo journalctl -u venya-executor --since "1 hour ago" | grep -i "cert\|rotate"

# Check cert expiry on executor
openssl x509 -in /etc/venya/executor/executor.crt -noout -enddate
```

Expected output:
```
notAfter=Nov  5 12:00:00 2025 GMT  # Should be ~30 days from now
```

---

## 2. Manual Executor Certificate Rotation

Force an executor to rotate its certificate early.

### Step 1: Revoke the old certificate (optional)

```bash
venya admin revoke-executor <executor_id>
```

This adds the executor's certificate serial number to the revocation list. The executor will detect this on its next revocation check (every 60 seconds) and disconnect.

### Step 2: Re-register the executor

On the executor machine:
```bash
# Stop the executor
sudo systemctl stop venya-executor

# Delete old cert and key
sudo rm -f /etc/venya/executor/executor.crt
sudo rm -f /etc/venya/executor/executor.key

# Start the executor — it will auto-register
sudo systemctl start venya-executor
```

Or manually:
```bash
# Generate new keypair + CSR
venya-executor generate-csr --executor-id <executor_id> --output /tmp/executor.csr

# Submit CSR to server (from server admin machine)
# The executor daemon handles this automatically on startup if no cert exists
```

### Step 3: Verify

```bash
# On server: check new cert is registered
# On executor: check cert expiry
openssl x509 -in /etc/venya/executor/executor.crt -noout -enddate
```

---

## 3. CA Key Backup

### 3a. Export CA Key (Encrypted)

```bash
venya admin export-ca-key \
  --output /mnt/backup/ca.key.encrypted \
  --ca-dir /etc/venya/ca
```

You will be prompted for a passphrase. Confirm it. The encrypted key is written to the output file with mode 0600.

### 3b. Split CA Key (Shamir's Secret Sharing)

```bash
venya admin split-ca-key \
  --threshold 3 \
  --shares 5 \
  --output-dir /mnt/backup/shares/ \
  --ca-dir /etc/venya/ca
```

This creates 5 share files:
```
/mnt/backup/shares/share-01
/mnt/backup/shares/share-02
/mnt/backup/shares/share-03
/mnt/backup/shares/share-04
/mnt/backup/shares/share-05
```

Any 3 shares can reconstruct the key. Distribute shares to different locations or administrators.

**Store shares:**
- Primary: Encrypted USB hardware token (YubiKey PIV slot or dedicated HSM)
- Secondary: Printed base64 on paper, stored in a physical safe
- Tertiary: Different physical locations (if using SSS)

### 3c. Export CA Certificate (for distribution)

```bash
venya admin export-ca-cert \
  --output /tmp/ca.crt \
  --ca-dir /etc/venya/ca
```

Transfer `ca.crt` out-of-band to executor machines (USB, secure copy during provisioning).

---

## 4. CA Key Restore

### 4a. Restore from Encrypted Backup

```bash
venya admin restore-ca-key \
  --mode backup \
  --backup-file /mnt/backup/ca.key.encrypted \
  --ca-dir /etc/venya/ca
```

Enter the passphrase when prompted. The CA key is restored to `/etc/venya/ca/ca.key` with mode 0600.

### 4b. Restore from Shares (SSS)

```bash
venya admin restore-ca-key \
  --mode shares \
  --shares /mnt/backup/shares/share-01 \
           /mnt/backup/shares/share-03 \
           /mnt/backup/shares/share-05 \
  --ca-dir /etc/venya/ca
```

Provide at least `threshold` share files. The shares are reconstructed and written to `/etc/venya/ca/ca.key`.

---

## 5. CA Key Rotation (Disaster Recovery)

If the CA key is compromised or lost and cannot be restored from backup, you must rotate the entire CA.

### Warning

Rotating the CA key invalidates ALL existing executor certificates. Every executor must be re-registered.

### Step 1: Backup existing CA (if possible)

```bash
# Backup current CA cert (for reference)
cp /etc/venya/ca/ca.crt /etc/venya/ca/ca.crt.old
```

### Step 2: Delete old CA and re-initialize

```bash
# Remove old CA files
sudo rm -f /etc/venya/ca/ca.key
sudo rm -f /etc/venya/ca/ca.crt

# Re-initialize CA (this creates a new CA keypair)
# This must be done on the Vault Server
venya init --skip-migrations
```

Note: `venya init` will fail if the system is already initialized. In this case, manually initialize the CA:

```python
# Python one-liner on the server
python3 -c "
from server.ca import CAManager
ca = CAManager('/etc/venya/ca')
ca.initialize()
print('CA re-initialized')
"
```

### Step 3: Distribute new CA certificate

```bash
# Export new CA cert
venya admin export-ca-cert --output /tmp/ca.crt

# Copy to each executor machine (out-of-band)
scp /tmp/ca.crt venya-executor@<executor-ip>:/tmp/ca.crt

# On each executor:
sudo cp /tmp/ca.crt /etc/venya/ca/ca.crt
sudo rm /tmp/ca.crt
```

### Step 4: Re-register all executors

On each executor machine:
```bash
sudo systemctl stop venya-executor
sudo rm -f /etc/venya/executor/executor.crt
sudo rm -f /etc/venya/executor/executor.key
sudo systemctl start venya-executor
```

The executor will auto-register with the new CA on startup.

### Step 5: Verify all executors

```bash
# On server: list all registered executors
curl -sk --cert /etc/venya/executor/server.crt \
     --key /etc/venya/executor/server.key \
     https://localhost:8080/api/v1/executors

# On each executor: check logs
sudo journalctl -u venya-executor --since "5 minutes ago"
```

---

## 6. Emergency Revocation

If an executor is compromised, revoke its certificate immediately.

```bash
venya admin revoke-executor <executor_id>
```

The executor will detect revocation within `revocation_poll_seconds` (default: 60s) and:
1. Abort any running commands
2. Clean up injected secrets
3. Disconnect from the server

Verify revocation:
```bash
# Check revocation list
curl -sk https://localhost:8080/api/v1/executors/certs/revocation-list

# Check executor status
sudo journalctl -u venya-executor --since "2 minutes ago" | grep -i revoke
```

---

## 7. Scheduled Maintenance Checklist

### Monthly

- [ ] Check executor certificate expiry: `openssl x509 -in /etc/venya/executor/executor.crt -noout -enddate`
- [ ] Review revocation list: `curl -sk https://localhost:8080/api/v1/executors/certs/revocation-list`
- [ ] Check CA key backup integrity (test restore in isolated environment)

### Quarterly

- [ ] Test CA key restore procedure in isolated environment
- [ ] Review and rotate CA key backup passphrases
- [ ] Audit executor registrations (remove decommissioned executors)
- [ ] Review revocation list (clean up stale entries if possible)

### Annually

- [ ] Consider CA key rotation (generate new CA, re-register all executors)
- [ ] Review certificate rotation interval (30 days may be adjusted)
- [ ] Test full disaster recovery procedure (CA loss + restore)
- [ ] Update this runbook with any procedure changes

---

## 8. Troubleshooting

### Executor fails to connect after cert rotation

```bash
# Check cert expiry
openssl x509 -in /etc/venya/executor/executor.crt -noout -dates

# Check CA cert on executor matches server
diff /etc/venya/ca/ca.crt /path/to/server/ca.crt

# Check executor logs
sudo journalctl -u venya-executor -n 50

# Check server logs for registration errors
sudo journalctl -u venya-vault -n 50 | grep -i "cert\|csr\|register"
```

### Revocation list not syncing

```bash
# Check revocation polling interval
grep revocation_poll_seconds /etc/venya/executor.toml

# Manually trigger revocation check
sudo systemctl restart venya-executor

# Check if executor is polling
sudo journalctl -u venya-executor -f | grep -i revocation
```

### CA key file has wrong permissions

```bash
# Fix permissions
sudo chown venya-vault:venya-vault /etc/venya/ca/ca.key
sudo chmod 600 /etc/venya/ca/ca.key

# Restart vault server
sudo systemctl restart venya-vault
```
