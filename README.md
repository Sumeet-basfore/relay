# Relay

**A local-first, zero-trust security gateway and credential broker for AI agents.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-green.svg)](SECURITY.md)
[![Tests](https://img.shields.io/badge/tests-380%20passed-brightgreen.svg)](crates/)

---

## Why Relay?

When you give an AI agent access to Model Context Protocol (MCP) tools, standard setups hand the agent raw API tokens (`GITHUB_TOKEN`, `DATABASE_URL`, SSH keys) and allow direct subprocess execution.

If the agent encounters an **indirect prompt injection** (from a malicious web page, repo issue, or data payload), the attacker gains full control over those ambient credentials and can execute unauthorized mutations: exfiltrating private keys, executing `DROP TABLE`, or wiping repositories.

Relay sits between the agent and tool execution to enforce **Authority + Credential Isolation + Evidence**:

1. **Cedar Policy Authorization (Default-Deny):** Every tool call is canonicalized and evaluated against deterministic [AWS Cedar](https://www.cedarpolicy.com/) policies before execution.
2. **JIT Credential Leasing:** The agent never holds long-lived secrets. Relay dynamically injects ephemeral, action-scoped credentials in memory for the microsecond duration of the tool execution.
3. **Linux Network Namespace Sandbox:** External MCP subprocesses are placed in an isolated network namespace. All outbound traffic routes through Relay's in-process loopback HTTP proxy, blocking raw-socket exfiltration.
4. **Cryptographic Action Receipts:** Every allowed or denied action produces a signed [DSSE / in-toto](https://in-toto.io/) attestation (Ed25519) stored in an append-only SQLite hash-chain ledger.
5. **Human-in-the-Loop Step-Up:** High-risk actions (e.g., file deletion, database DDL) can require explicit confirmation on `/dev/tty` before execution.

---

## Architecture

```text
       Untrusted AI Agent (Claude, Cursor, custom loop)
                              │
                              │ stdio JSON-RPC (tools/call)
                              ▼
               ┌──────────────────────────────┐
               │        RELAY GATEWAY         │
               ├──────────────────────────────┤
               │ 1. Canonicalize Request (JCS)│
               │ 2. Authorize via Cedar Engine│
               │ 3. Step-Up Approval (/dev/tty)
               │ 4. Issue JIT Credential Lease│
               │ 5. Execute in Linux Sandbox  │
               │ 6. Sign DSSE Action Receipt  │
               │ 7. Record to Hash-Chain DB   │
               └──────────────┬───────────────┘
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
          Filesystem      PostgreSQL      GitHub / HTTP Egress
          (Sandboxed)   (Scoped Queries) (Namespace Isolated)
```

---

## Example Cedar Policy

Policies use the formal [Cedar policy language](https://www.cedarpolicy.com/) and are strictly default-deny:

```cedar
// 1. Allow reading public files
permit(
    principal,
    action == Relay::Action::"fs:read",
    resource in Relay::Resource::"/workspace/public"
);

// 2. Forbid access to sensitive paths under any circumstances
forbid(
    principal,
    action,
    resource in Relay::Resource::"~/.ssh"
);

// 3. Require human approval for file deletions
permit(
    principal,
    action == Relay::Action::"fs:delete",
    resource
) when {
    context.has_approval == true
};
```

---

## Installation & Setup

### Option 1: Build from Source (Cargo)

Prerequisites: Rust 1.78+ (`rustup default stable`).

```bash
# Clone the repository
git clone https://github.com/Sumeet-basfore/relay.git
cd relay

# Build optimized release binary
cargo build --release

# The binary is placed at target/release/relay
./target/release/relay --version
```

### Option 2: Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/Sumeet-basfore/relay/main/install.sh | bash
```

---

## Quickstart & CLI Commands

### 1. Check System Health & Security Dependencies
Verifies keyring storage, signing keys, and ledger initialization:
```bash
./target/release/relay doctor
# or via cargo:
cargo run --bin relay -- doctor
```

### 2. Wrap and Govern an MCP Server
Interpose Relay in front of any stdio MCP server:
```bash
./target/release/relay run -- my-mcp-server --stdio
```

To use a custom policy directory and pass vaulted environment variables:
```bash
./target/release/relay run --policy ./policies --env GITHUB_TOKEN=vault:gh_token -- my-mcp-server
```

### 3. Manage Vaulted Secrets
Store secrets securely in the OS native keyring:
```bash
# Store a secret
./target/release/relay secret set github_token "ghp_xxxxxxxxxxxx"

# List stored secret aliases (values remain masked)
./target/release/relay secret list
```

### 4. Validate Cedar Policies
Check policy syntax and schema consistency:
```bash
./target/release/relay policy validate --path ./policies
```

### 5. Launch Local Security Console (Web UI)
Start the local dashboard at `http://127.0.0.1:8765` to inspect live tool calls, policy evaluations, and audit logs:
```bash
./target/release/relay ui
```
*Tip:* Run `./target/release/relay ui --no-browser --port 4040` for headless environments.

### 6. Inspect & Verify Action Receipts
Inspect tamper-evident audit records:
```bash
# List recent action receipts
./target/release/relay receipt list --limit 10

# Inspect a specific receipt
./target/release/relay receipt get <RECEIPT_UUID_OR_HASH>

# Cryptographically verify the SQLite hash-chain ledger
./target/release/relay verify
```

---

## Automated Golden Demo & Attack Probes

Relay includes a disposable, automated 7-scene demonstration showing policy enforcement, SQL injection blocking, step-up approvals, and network namespace defense:

```bash
# Run the complete end-to-end demo
./scripts/demo/run.sh

# Run targeted adversarial attack probes
./scripts/demo/attack.sh

# Clean up demo artifacts
./scripts/demo/cleanup.sh
```

---

## Running Tests

Relay features 380+ automated unit, integration, and security tests:

```bash
# Run all workspace tests
cargo test --workspace --all-features

# Run specific crate tests
cargo test -p relay-policy       # Cedar authorization
cargo test -p relay-receipts     # DSSE signing & cryptography
cargo test -p relay-mcp          # MCP gateway & network sandbox
cargo test -p relay-connectors   # Filesystem, Postgres, GitHub connectors

# Linter and formatting checks
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check
```

---

## Security Model & Boundaries

| Protected Against | Out of Scope / Not Protected |
|---|---|
| **Indirect prompt injection:** Compromised agent cannot bypass Cedar policies. | **Host root/kernel compromise:** Attacker with root can bypass OS controls. |
| **Ambient credential exposure:** Agent never sees raw tokens or keys in memory/env. | **Permissive policies:** Misconfigured `permit(any)` rules will allow actions. |
| **Network socket exfiltration:** Subprocess raw network access is sandboxed in Linux netns. | **Non-Linux sandboxing:** macOS/Windows use managed cooperative proxy mode. |
| **Audit tampering:** Signed DSSE receipts in a cryptographic SQLite hash chain. | **Remote cloud eventual consistency:** Proves Relay's observation locally. |

For the complete threat model and invariant specifications, see [`docs/security/`](docs/security/README.md).

---

## Repository Structure

```text
crates/
├── relay-domain       # Core domain entities, errors, and state machines
├── relay-canonical    # RFC 8785 JSON Canonicalization Scheme (JCS)
├── relay-policy       # Cedar policy engine and request mappers
├── relay-credentials   # JIT credential lease broker and OS keyring integration
├── relay-receipts     # RFC 9598 DSSE / in-toto v1.0 signing (Ed25519)
├── relay-connectors   # Native Filesystem, PostgreSQL, and GitHub connectors
├── relay-mcp          # MCP stdio gateway, HTTP loopback proxy, and Linux netns sandbox
├── relay-ledger       # Append-only SQLite hash-chain audit ledger
└── relay-cli          # CLI commands, daemon, and local web UI console
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
