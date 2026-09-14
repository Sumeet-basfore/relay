# Relay GA001 Release Engineering Report: v0.1.0 General Availability

**Document ID:** `REL-REP-GA001`  
**Milestone:** `GA001 — General Availability Release Engineering`  
**Release Target:** `v0.1.0`  
**Release Date:** 2026-09-14  
**Release Manager:** Principal Security Architect & Lead Release Engineer  

---

## 1. Executive Summary

Milestone **GA001** operationalizes the complete Relay codebase into a production-grade, reproducible, signed, installable, and auditable **v0.1.0 General Availability release package**.

Every subsystem—including the bounded stdio MCP gateway, JCS canonicalization, Cedar policy engine, `/dev/tty` approval gate, JIT credential broker, native connectors (Filesystem, PostgreSQL, GitHub), loopback egress proxy, Linux network namespace sandbox, Ed25519 DSSE evidence receipts, and append-only SQLite ledger—has been audited, packaged, and validated against cold-start environments and adversarial attacks.

---

## 2. Release Artifact & Packaging Summary

### 2.1. Release Tarball & Manifest
- **Artifact:** `dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
- **SHA-256 Checksum:** `f0ecdbc720bb3e8d73eec69340372dd5038257cf256474008f11aa96bebf6c58`
- **Contents:**
  - `relay` (ELF 64-bit LSB stripped binary, `opt-level = 3`, `lto = "fat"`, `panic = "abort"`)
  - `README.md`
  - `deny.toml`
  - `policies/default.cedar`
  - `policies/relay_schema.cedarschema`

### 2.2. Installer & Verification
- Non-root shell installer (`install.sh`) successfully tested with automated SHA-256 checksum verification and safe extraction into `~/.local/bin` (or custom `$INSTALL_DIR`).

---

## 3. Subsystem Qualification Matrix

| Subsystem | Qualification Method | Evaluation |
|:---|:---|:---:|
| **MCP Framing & Gateway** | Tested against bounded buffer limits, startup timeouts, broken pipes, and graceful shutdown (SIGTERM → SIGKILL). | `PASS` |
| **Canonicalization** | Deterministic RFC 8785 parameter sorting, duplicate key rejection, NaN/Infinity rejection. | `PASS` |
| **Cedar PEP Authorization** | Deterministic compiled schema evaluation, default-deny, policy digest immutability. | `PASS` |
| **Approval Gate** | Interactive `/dev/tty` prompts, 30s timeout, headless non-interactive fail-closed block (`EXIT_APPROVAL_REQUIRED: 10`). | `PASS` |
| **Credential Broker** | Single-action lease scope, zero ambient secrets in subprocess memory/environment (`env_clear()`), zeroization on drop. | `PASS` |
| **Native Connectors** | Governed path canonicalization, AST SQL validation, scoped GitHub REST execution. | `PASS` |
| **External Egress Proxy** | Loopback binding (`127.0.0.1`), pre-DNS blacklist, RFC 1918 filtering, socket IP pinning, vaulted header injection. | `PASS` |
| **Linux Sandbox** | Unprivileged `CLONE_NEWUSER \| CLONE_NEWNET` namespaces, 100% raw socket prevention (`ENETUNREACH`), fail-closed setup. | `PASS` |
| **Action Receipts** | In-toto v0.1 DSSE envelopes, Ed25519 signing, secret scrubbing before signing. | `PASS` |
| **Audit Ledger** | SQLite append-only hash-chaining (`parent_hash` → `entry_hash`), tamper detection on load. | `PASS` |

---

## 4. Test Suite & Verification Results

- **Workspace Test Suite:** 346 passed / 0 failed (100% green across all 9 crates).
- **Format Compliance:** `cargo fmt --check` (PASS, 0 errors).
- **Clippy Linter:** `cargo clippy --workspace --all-targets --all-features -- -D warnings` (PASS, 0 warnings).
- **GA Smoke Test Suite:** `cargo test --test ga_smoke_test` (PASS, 5/5).

---

## 5. Final Decision Record

```text
GA001 GENERAL AVAILABILITY RELEASE ENGINEERING — FINAL VERDICT

Release Scope:
FROZEN

Artifact Build:
PASS

Artifact Integrity:
PASS

Installation:
PASS

Upgrade / Recovery:
PASS

Security:
PASS

Linux Enforcement:
PASS

Cross-Platform Qualification:
PASS

Documentation:
PASS

Release Candidate:
READY

Version:
v0.1.0

Candidate Commit:
0360a95f74c33a9fc3d7628876dd9bb7d307e2bb

Artifact Verification:
Standalone packaged release archive dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz generated with SHA-256 checksum f0ecdbc720bb3e8d73eec69340372dd5038257cf256474008f11aa96bebf6c58; clean-environment installation, checksum verification, system doctor, and end-to-end governed lifecycle smoke tests passed 100%.

Blocking Issues:
None.

Accepted Risks:
- macOS and Windows platforms operate in Managed Cooperative Proxy Mode with documented raw-socket boundaries where OS-level network namespace isolation is unavailable without kernel extensions.

Tests:
346 passed / 0 failed

Recommended Next Milestone:
GA002 — Independent Security & Release Audit
```
