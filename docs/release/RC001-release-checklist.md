# Relay RC001 — Release Verification Checklist

**Document Version:** 1.0.0  
**Target Release:** Relay v0.1.0-rc.1  
**Evaluator:** Release Engineering & Security Assurance  
**Date:** 2026-09-14  
**Workspace:** `relay`

---

## 1. Environment Prerequisites

| Item ID | Verification Check | Expected Outcome | Status |
|:---|:---|:---|:---:|
| **ENV-01** | Rust Toolchain | `rustc --version` $\ge$ 1.78.0 (`rustc 1.85.0` or stable) | **PASS** |
| **ENV-02** | Cargo Package Manager | `cargo --version` operational | **PASS** |
| **ENV-03** | Operating System | Linux (x86_64 / aarch64), macOS, or Windows | **PASS** |
| **ENV-04** | SQLite Support | Bundled SQLite via `rusqlite` (no external runtime library required) | **PASS** |
| **ENV-05** | Terminal Interface | `/dev/tty` accessible on interactive Unix hosts | **PASS** |

---

## 2. Compilation and Build Verification

| Item ID | Verification Check | Command | Status |
|:---|:---|:---|:---:|
| **BLD-01** | Clean Checkout Build | `cargo build --workspace` | **PASS** |
| **BLD-02** | Release Optimization Build | `cargo build --release` | **PASS** |
| **BLD-03** | Binary Generation | `test -f target/release/relay` | **PASS** |
| **BLD-04** | Static Binary Stripping | Binary symbols stripped; release size $\approx 14\text{ MB}$ | **PASS** |
| **BLD-05** | Formatter Compliance | `cargo fmt --all -- --check` returns 0 | **PASS** |
| **BLD-06** | Clippy Quality Gate | `cargo clippy --workspace --all-targets -- -D warnings` returns 0 | **PASS** |

---

## 3. Automated Test Suite Execution

| Item ID | Test Target | Command | Result | Status |
|:---|:---|:---|:---|:---:|
| **TST-01** | Canonicalization & AST | `cargo test -p relay-canonical` | 38 passed / 0 failed | **PASS** |
| **TST-02** | Domain & State Machines | `cargo test -p relay-domain` | 34 passed / 0 failed | **PASS** |
| **TST-03** | Cedar Policy Engine | `cargo test -p relay-policy` | 26 passed / 0 failed | **PASS** |
| **TST-04** | JIT Credential Broker | `cargo test -p relay-credentials` | 15 passed / 0 failed | **PASS** |
| **TST-05** | Receipts & DSSE Signatures | `cargo test -p relay-receipts` | 35 passed / 0 failed | **PASS** |
| **TST-06** | Append-Only Ledger | `cargo test -p relay-ledger` | 28 passed / 0 failed | **PASS** |
| **TST-07** | Connectors & Adversarial Rig | `cargo test -p relay-connectors` | 89 passed / 0 failed | **PASS** |
| **TST-08** | MCP Gateway & Framing | `cargo test -p relay-mcp` | 22 passed / 0 failed | **PASS** |
| **TST-09** | CLI & Hardening Suite | `cargo test -p relay-cli` | 22 passed / 0 failed | **PASS** |
| **TST-10** | Full Workspace Regression | `cargo test --workspace` | 309 passed / 0 failed | **PASS** |

---

## 4. Security & Hardening Invariant Checks

| Invariant ID | Security Assertion | Verification Method | Status |
|:---|:---|:---|:---:|
| **SEC-01** | **Zero Ambient Credentials (G1)** | Agent environment contains no ambient credentials; secrets scrubbed from memory on drop. | **PASS** |
| **SEC-02** | **Complete Mediation (G2)** | Governed tools strictly evaluated by Cedar; unregistered tools fail closed. | **PASS** |
| **SEC-03** | **Canonical Integrity (G3)** | RFC 8785 JCS ensures duplicate keys rejected and identical ASTs yield identical `ActionHash`. | **PASS** |
| **SEC-04** | **Approval Integrity (G4)** | Approvals bound to `ActionHash`; expired approvals or mismatched hashes fail closed. | **PASS** |
| **SEC-05** | **Credential Binding (G5)** | Single-action JIT leases cannot be reused or rebound to divergent actions. | **PASS** |
| **SEC-06** | **Evidence Integrity (G6)** | Ed25519 DSSE envelopes detect any payload or signature modification. | **PASS** |
| **SEC-07** | **Ledger Immutability (G7)** | SQLite triggers prevent UPDATE/DELETE; hash chain detects row modification. | **PASS** |
| **SEC-08** | **Fail-Closed Behavior (G8)** | Headless gate blocks approvals with exit code 7; parse errors return negative JSON-RPC error. | **PASS** |
| **SEC-09** | **Secret Debug Masking** | `PostgresCredentials`, `SecretBuffer`, `SigningKey` emit `[REDACTED]` in `Debug`. | **PASS** |
| **SEC-10** | **Filesystem Permissions** | Ledger file created with `0600`; ledger parent directory created with `0700` on Unix. | **PASS** |
| **SEC-11** | **Subprocess Sanitization** | `env_clear()` called before spawning child MCP server; safe whitelist restored. | **PASS** |

---

## 5. Release Artifact & CLI Smoke Test

```bash
# 1. Verify diagnostic health check
./target/release/relay doctor

# 2. Verify help and version flags
./target/release/relay --version
./target/release/relay --help

# 3. Verify ledger verification on clean database
./target/release/relay verify --ledger .relay/ledger.db
```

| Item ID | Smoke Test Action | Observed Outcome | Status |
|:---|:---|:---|:---:|
| **SMK-01** | `relay doctor` | Reports system health, TTY state, and config directories cleanly | **PASS** |
| **SMK-02** | `relay --version` | Outputs `relay 0.1.0` | **PASS** |
| **SMK-03** | `relay --help` | Outputs structured CLI usage | **PASS** |
| **SMK-04** | Missing command after `run` | Exits with code `2` (`EXIT_CONFIG_ERROR`) | **PASS** |
| **SMK-05** | `relay verify` on valid chain | Verifies hash chain and DSSE signatures successfully | **PASS** |

---

## 6. Known Limitations & Accepted Risks

| ID | Category | Description | Status |
|:---|:---|:---|:---:|
| **LIM-01** | Deployment Model | SQLite ledger file security relies on host OS user DAC permissions (`0600`). | **ACCEPTED RISK** |
| **LIM-02** | API Visibility | Native connector struct methods (`execute`) should be reduced to `pub(crate)` in post-MVP v0.2.0. | **ACCEPTED RISK** |
| **LIM-03** | External Egress Proxy | HTTP egress proxy for non-stdio external MCP servers is scheduled for post-MVP milestone. | **NOT APPLICABLE** |

---

## 7. Release Blockers

| Blocker ID | Description | Resolution | Status |
|:---|:---|:---|:---:|
| **BLK-NONE** | No unresolved release blockers identified | All 8 security claims verified; 100% tests green. | **PASS** |

---

## 8. Release Sign-Off

**Milestone Verdict:** `RELEASE CANDIDATE APPROVED (RC001)`  
**Release Readiness:** `READY WITH CONDITIONS`
