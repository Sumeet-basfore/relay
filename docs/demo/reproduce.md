# Relay v0.1.0 — Golden Reference Demo Reproduction Guide

This guide enables security engineers and operators to independently reproduce the **Relay Golden Reference Demonstration** from source or pre-built release artifacts.

---

## 1. Prerequisites

* **Operating System:** Linux (x86_64 or aarch64, Kernel ≥ 5.4 recommended) or macOS / Windows (Managed Cooperative Mode)
* **Rust Toolchain:** Stable Rust 1.85+ (if building from source)
* **Python:** Python 3.8+ (for deterministic demo MCP server, standard library only, 0 third-party packages required)
* **Utilities:** `bash`, `sqlite3` (optional for manual inspection)

---

## 2. Quick Start (One Command)

To run the complete reference demonstration end-to-end:

```bash
# Clone and enter repository
git clone https://github.com/relay-security/relay.git
cd relay

# Run the complete automated demonstration
./scripts/demo/run.sh
```

---

## 3. Step-by-Step Manual Execution

### Step 1: Initialize Disposable Environment
```bash
./scripts/demo/setup.sh
```
This creates an isolated workspace at `/tmp/relay-golden-demo/` containing:
* `relay.toml` configured with default-deny and 0600 permissions
* `policies/demo.cedar` and `policies/relay_schema.cedarschema`
* `fixtures/public.txt` and `fixtures/protected.txt`
* `server.py` (Adversarial & Governed MCP Server)

### Step 2: Verify Configuration Health
```bash
cd /tmp/relay-golden-demo
relay --config relay.toml doctor
```
Expected output:
* Target OS: `linux`
* Egress Sandbox Mode: `Linux Enforced Network Namespace Sandbox [ACTIVE/ENFORCED]`

### Step 3: Execute Governed MCP Session
```bash
relay --config relay.toml run -- python3 server.py
```

### Step 4: Run Targeted Adversarial Attack Probes
```bash
./scripts/demo/attack.sh
```
Executes targeted probes against:
* Ambient credential exfiltration
* Host loopback connection (`127.0.0.1:8080`)
* Cloud Metadata IMDS (`169.254.169.254`)
* Private RFC 1918 subnets (`10.0.0.1`)
* Direct raw TCP sockets (Linux namespace block)
* Post-action session reuse

### Step 5: Cryptographic Ledger Verification
```bash
cd /tmp/relay-golden-demo
relay --config relay.toml verify
```
Expected output:
```text
==================================================
   Relay Cryptographic Ledger Verification
==================================================
Status:           ✓ VALID (Hash chain and signatures verified)
==================================================
```

### Step 6: Test Tamper Detection
```bash
cd /tmp/relay-golden-demo
cp .relay/ledger.db .relay/tampered.db

# Corrupt single byte in database
python3 -c "
with open('.relay/tampered.db', 'r+b') as f:
    d = bytearray(f.read())
    d[4000] ^= 0xFF
    f.seek(0)
    f.write(d)
"

# Verify tampered database fails closed
relay verify --ledger .relay/tampered.db
```
Expected output: Non-zero exit code with `FAILED: Payload/Hash mismatch`.

---

## 4. Cleaning Up

```bash
./scripts/demo/cleanup.sh
```
Safely deletes `/tmp/relay-golden-demo/` and all ephemeral demonstration state.
