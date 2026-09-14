# Relay

**A local-first, zero-trust MCP Security Gateway and Credential Broker for AI agents.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-green.svg)](SECURITY.md)
[![Status](https://img.shields.io/badge/status-Release%20Candidate%20(v0.1.0)-success.svg)](docs/release/RC002-release-report.md)

---

## 1. What is Relay?

Relay is a lightweight, standalone Rust binary that interposes between AI agents (e.g., Claude, Cursor, custom agent loops) and Model Context Protocol (MCP) tools.

Relay enforces a hard, deterministic security boundary:
1. **Deterministic Cedar Authorization:** Authorizes tool actions with formal AWS Cedar policies rather than probabilistic LLM heuristics.
2. **Ambient Credential Elimination:** Completely prevents target API tokens, database credentials, and private keys from entering agent context windows, disk files, or subprocess memory.
3. **Cryptographic Action Receipts:** Produces signed RFC 9598 DSSE / in-toto v1.0 attestations for every executed action, recorded in an append-only SQLite hash-chain ledger.

```text
               UNTRUSTED AGENT
            Claude / Cursor / Agent
                       │
                       │ stdio (tools/call)
                       ▼
          ┌─────────────────────────┐
          │      RELAY GATEWAY      │
          ├─────────────────────────┤
          │ 1. Canonicalize (JCS)   │
          │ 2. Authorize (Cedar)    │
          │ 3. Human Gate (/dev/tty)│
          │ 4. JIT Credential Lease │
          │ 5. Native In-Process Exec│
          │ 6. DSSE Action Receipt  │
          │ 7. Append-Only Ledger   │
          └─────────────────────────┘
                       │
           ┌───────────┼───────────┐
           ▼           ▼           ▼
       Filesystem  PostgreSQL   GitHub
```

---

## 2. What Problem Does Relay Solve?

Today, giving an AI agent access to tools usually means granting it **ambient credentials** (e.g. `GITHUB_TOKEN`, `DATABASE_URL`, or broad filesystem access) directly within its environment.

When an agent suffers an **indirect prompt injection** (from a malicious web page, untrusted repository file, or database entry), the attacker gains full control over those ambient credentials and can execute destructive actions (exfiltrating SSH keys, dropping tables, or deleting repositories).

Relay solves this by separating **proposing an action** from **authorizing and executing an action**:
- The agent proposes actions in plain text.
- Relay normalizes the request into a canonical representation.
- Relay checks Cedar security policies before any credential is leased or any tool is dispatched.
- Leased credentials exist only for the microsecond duration of the tool execution in protected memory.

---

## 3. What Relay Protects vs. What It Does Not Protect

### What Relay Protects:
- **Credential Isolation:** Agent processes never observe target API tokens (GitHub PATs, DB passwords) in memory or environment.
- **Blast Radius Confinement:** Under 100% prompt-injection compromise, the agent cannot exceed what is explicitly permitted by Cedar policies.
- **Tamper-Evident Evidence:** All actions produce signed, hash-chained receipts verifying who executed what, when, and under which policy version.

### What Relay Does Not Protect (Out of Scope):
- **Host OS Compromise:** If an attacker has `root` access or compromised the host kernel, they can bypass local software controls.
- **Remote Cloud State:** A receipt proves Relay's observation; it does not guarantee remote eventual consistency or prevent remote server failures.
- **Insecure User Policies:** If an administrator writes a permissive policy (`permit(principal, action, resource);`), Relay will authorize those actions.

For detailed non-goals, see [What Relay Does Not Do](docs/security/limitations.md).

---

## 4. Installation

### Quick Install (Non-Root)
```bash
curl -fsSL https://raw.githubusercontent.com/relay-security/relay/main/install.sh | bash
```

### Manual Installation
Download the release tarball and SHA-256 manifest from [Releases](https://github.com/relay-security/relay/releases), verify the checksum, and copy the binary to your `PATH`:
```bash
sha256sum --check SHA256SUMS
tar -xzf relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cp relay-v0.1.0-x86_64-unknown-linux-gnu/relay ~/.local/bin/
```

Verify installation:
```bash
relay --version
relay doctor
```

---

## 5. Quick Start: Running Governed Actions

### Step 1: Diagnose Health & Configuration
```bash
relay doctor
```

### Step 2: Wrap and Govern an MCP Server
```bash
relay run -- my-mcp-server --stdio
```

### Step 3: Cryptographically Verify the Audit Ledger
```bash
relay verify
```

### Step 4: Inspect Generated Action Receipts
```bash
relay receipt list
```

---

## 6. Golden Reference Demo & Adversarial Attack Suite

Relay includes a canonical, fully automated, disposable Golden Reference Demonstration that proves its security properties across native connectors, Linux network namespace sandboxing, anti-SSRF filters, and cryptographic tamper detection:

```bash
# Run the complete end-to-end golden demonstration
./scripts/demo/run.sh

# Run targeted adversarial attack probes
./scripts/demo/attack.sh

# Clean up all disposable demo state
./scripts/demo/cleanup.sh
```

For detailed reference materials:
- **[Golden Reference Architecture](docs/demo/golden-reference.md)**: Canonical topologies, sandboxing modes, and invariant mappings.
- **[Demo Presentation Script](docs/demo/demo-script.md)**: Turn-by-turn presenter script for live 10-minute demonstrations.
- **[Reproduction Manual](docs/demo/reproduce.md)**: Step-by-step reproduction instructions for independent security reviewers.

---

## 7. Security Documentation Suite

Relay's complete security architecture is fully specified in `docs/security/`:

- **[Security Overview & Index](docs/security/README.md)**
- **[Threat Model](docs/security/threat-model.md)**
- **[Formal Security Invariants](docs/security/security-invariants.md)**
- **[Evidence & Receipt Model](docs/security/evidence-model.md)**
- **[Credential Security Model](docs/security/credential-model.md)**
- **[Policy Security Model](docs/security/policy-model.md)**
- **[Native Connector Security](docs/security/connectors.md)**
- **[MCP Mediation Boundary](docs/security/mcp-boundary.md)**
- **[Prompt Injection Analysis](docs/security/prompt-injection.md)**
- **[Security Claims Matrix](docs/security/security-claims.md)**
- **[What Relay Does Not Do](docs/security/limitations.md)**
- **[Secure Deployment Guide](docs/security/secure-deployment.md)**
- **[Vulnerability Disclosure Policy](SECURITY.md)**

---

## 7. License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
