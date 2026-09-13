# A010: Relay MVP Build Specification & Implementation Contract

**Document ID:** `A010-build-specification`  
**Date:** September 2026  
**Status:** Frozen Implementation Contract / Final Architecture Baseline  
**Target System:** Relay MVP (Local-First Zero-Trust MCP Security Gateway & Credential Broker)  
**Author:** Lead Systems Architect  
**Corpus Dependencies:** `00-research-synthesis`, `A001`–`A009`, `R001`–`R015`

---

## Executive Summary

This document establishes the **binding implementation contract** for the Relay MVP. It translates and freezes the validated architectural decisions from `A001` through `A009` into an actionable, non-negotiable engineering blueprint.

### Purpose of this Specification
1. **Zero Architectural Drift:** This document does **NOT** introduce new architecture. It codifies the final, approved system design, domain entities, interfaces, security invariants, persistence schemas, CLI commands, and dependency sets.
2. **Implementation Ready:** A systems engineer implementing Relay in Rust can execute the milestone build plan sequentially without needing to make fundamental architectural choices on their own.
3. **Formal Handoff:** This specification serves as the formal handoff from Architecture to Engineering.

---

## Table of Contents

1. [Frozen Architecture Summary](#1-frozen-architecture-summary)
2. [Frozen Domain Model](#2-frozen-domain-model)
3. [Frozen Interfaces & Type-State Contracts](#3-frozen-interfaces--type-state-contracts)
4. [Frozen Security Invariants](#4-frozen-security-invariants)
5. [Frozen Persistence Model & Schemas](#5-frozen-persistence-model--schemas)
6. [Frozen CLI Surface](#6-frozen-cli-surface)
7. [Frozen Rust Dependency Set](#7-frozen-rust-dependency-set)
8. [Vertical Implementation Milestones (B001–B012)](#8-vertical-implementation-milestones)
9. [Definition of Done (DoD)](#9-definition-of-done)
10. [Explicitly Frozen Non-Goals](#10-explicitly-frozen-non-goals)
11. [Architecture Change Protocol](#11-architecture-change-protocol)

---

## 1. Frozen Architecture Summary

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   RELAY FROZEN ARCHITECTURE MAP                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

   [ UNTRUSTED AGENT RUNTIME ]                     [ RELAY CORE TRUSTED COMPUTING BASE (TCB) ]
 ┌─────────────────────────────┐                  ┌─────────────────────────────────────────────────┐
 │ Claude Desktop / Cursor CLI │                  │ Process: `relay` (UID: user, PR_SET_DUMPABLE: 0)│
 └──────────────┬──────────────┘                  │                                                 │
                │                                 │  ┌───────────────────┐  ┌────────────────────┐  │
                │ stdio (JSON-RPC 2.0 / 4MB max)  │  │ Stdio Gateway     │  │ In-Process Cedar   │  │
                ▼                                 │  │ & RFC 8785 (JCS)  │─►│ Policy Engine (PDP)│  │
 ══════════════════════════════ [TRUST BOUNDARY 1]│  └─────────┬─────────┘  └────────────────────┘  │
                                                  │            │                                    │
                                                  │            ▼                                    │
                                                  │  ┌───────────────────┐  ┌────────────────────┐  │
                                                  │  │ Type-State        │  │ JIT Credential     │  │
                                                  │  │ Execution Engine  │─►│ Broker (Keyring)   │  │
                                                  │  └─────────┬─────────┘  └──────────┬─────────┘  │
                                                  │            │                       │            │
                                                  │            ├───────────────────────┘            │
                                                  │            ▼                                    │
                                                  │  ┌───────────────────┐  ┌────────────────────┐  │
                                                  │  │ Native Connectors │  │ Loopback Egress    │  │
                                                  │  │ (GitHub/PG/FS)    │  │ Proxy (Token Auth) │  │
                                                  │  └─────────┬─────────┘  └──────────┬─────────┘  │
                                                  │            │                       │            │
                                                  │            ▼                       ▼            │
                                                  │  ┌───────────────────────────────────────────┐  │
                                                  │  │ DSSE in-toto v1.0 Signer (Ed25519)        │  │
                                                  │  │ & SQLite Append-Only Ledger (`ledger.db`) │  │
                                                  │  └───────────────────────────────────────────┘  │
                                                  └────────────────────────┬────────────────────────┘
                                                                           │
                                                                           ▼
 ══════════════════════════════════════════════════════════════════════════════════════════════════ [TB 2]
   [ TARGET SERVICES & EXECUTION ]
 ┌─────────────────────────────┐  ┌─────────────────────────────┐  ┌────────────────────────────────┐
 │ api.github.com (JIT Bearer) │  │ PostgreSQL (JIT Conn String)│  │ Sandboxed Workspace Filesystem │
 └─────────────────────────────┘  └─────────────────────────────┘  └────────────────────────────────┘
```

* **Process Model:** Single monolithic Rust executable (`relay`) running locally on the user host. Operates as an async Tokio runtime with an isolated single-writer thread for the SQLite ledger.
* **Trust Boundaries:** The agent process, prompt context, and memory are **UNTRUSTED** and hold zero target secrets. Relay Core is the **TRUSTED COMPUTING BASE (TCB)**. Third-party MCP child subprocesses are **PARTIALLY TRUSTED** (spawned with scrubbed environments and forced through Relay's authenticated loopback proxy).
* **Execution Model:** Dual-track execution:
  1. *Track 1 (Native In-Process Connectors):* GitHub, PostgreSQL, and Filesystem connectors execute inside Relay using ephemeral, zeroized memory leases.
  2. *Track 2 (Governed Subprocesses):* Subprocesses spawned via `tokio::process` with cleared environments; outbound HTTP calls authenticate against Relay's local loopback proxy (`127.0.0.1:0`) via an ephemeral 128-bit bearer token (`RELAY_PROXY_AUTH`).
* **MCP Gateway:** Stdio transport, newline-delimited JSON-RPC 2.0 framing, 4 MB frame limits, deterministic tool namespacing (`<server>.<tool>`), and startup tool schema digest pinning.
* **Policy Engine:** AWS Cedar (`cedar-policy` crate) embedded in-process. Strictly default-deny. Evaluates compiled Cedar policies on normalized canonical entity representations in $< 2\text{ ms}$.
* **Credential Broker:** Hardware OS Keyring (Keychain / SecretService) with memory-safe `zeroize` and virtual memory locking (`mlock`). Ephemeral single-action leases.
* **Approval Engine:** Direct `/dev/tty` interactive step-up terminal prompts, dynamically bound to the SHA-256 parameter digest (`ActionHash`). Fail-closed in headless/CI environments.
* **Receipts & Ledger:** in-toto Statement v1.0 enveloped in DSSE (RFC 9598), signed via Ed25519, and persisted to a local WAL-mode SQLite database chained via SHA-256 blocks.

---

## 2. Frozen Domain Model

The domain model consists strictly of **12 canonical entities** and **4 value objects** defined in `A002-domain-model.md`.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     CANONICAL DOMAIN INVENTORY                                   │
├───────────────────┬──────────────┬────────────────────────┬──────────────────────────────────────┤
│ Name              │ Type         │ Unique Identifier      │ Lifecycle / Mutability               │
├───────────────────┼──────────────┼────────────────────────┼──────────────────────────────────────┤
│ `Principal`       │ Entity       │ `PrincipalId` (URN)    │ Ephemeral, immutable                 │
│ `Agent`           │ Entity       │ `AgentId` (URN)        │ Configured, immutable                │
│ `Session`         │ Entity       │ `SessionId` (`sess_`)  │ Created -> Active -> Terminated      │
│ `Tool`            │ Entity       │ `ToolId` (`srv.tool`)  │ Discovered -> Pinned                 │
│ `Resource`        │ Value Object │ `ResourceUri` (URN)    │ Immutable                            │
│ `Action`          │ Entity       │ `ActionId` (`act_`)    │ Proposed -> Authz -> Executed/Denied │
│ `AuthorizationReq`│ Value Object │ `ActionHash` (SHA-256) │ Immutable                            │
│ `PolicyDecision`  │ Value Object │ `DecisionId` (`dec_`)  │ Immutable (`Allow` / `Deny` / `Adv`) │
│ `Approval`        │ Entity       │ `ApprovalId` (`appr_`) │ Pending -> Approved / Rejected       │
│ `CredentialLease` │ Value Object │ `LeaseId` (`lease_`)   │ Ephemeral, affine single-use         │
│ `Execution`       │ Entity       │ `ExecutionId` (`exec_`)| Pending -> Running -> Complete/Fail  │
│ `ExecutionResult` │ Value Object │ `OutputHash` (SHA-256) │ Immutable                            │
│ `ActionReceipt`   │ Entity       │ `ReceiptHash` (SHA-256)│ Immutable, signed DSSE envelope      │
│ `LedgerEntry`     │ Entity       │ `SequenceNumber` (u64) │ Append-only, SHA-256 chained         │
└───────────────────┴──────────────┴────────────────────────┴──────────────────────────────────────┘
```

### Core Entity Relationships
$$\text{Session} \xrightarrow{1..*} \text{Action} \xrightarrow{1..1} \text{AuthorizationReq} \xrightarrow{1..1} \text{PolicyDecision}$$
$$\text{PolicyDecision} \xrightarrow{\text{if Advice}} \text{Approval} \xrightarrow{\text{if Allowed}} \text{CredentialLease} \xrightarrow{1..1} \text{Execution} \xrightarrow{1..1} \text{ActionReceipt} \xrightarrow{1..1} \text{LedgerEntry}$$

---

## 3. Frozen Interfaces & Type-State Contracts

The type-state pipeline enforces that an action **cannot be physically executed without a compiled cryptographic capability token** (`AuthorizedAction<State>`).

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   TYPE-STATE PIPELINE CONTRACT                                   │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│   Incoming Frame ──► `ParsedRpcRequest`                                                          │
│                             │                                                                    │
│                             ▼ `canonicalize()`                                                   │
│                      `NormalizedRequest`                                                         │
│                             │                                                                    │
│                             ▼ `PolicyEngine::evaluate()`                                         │
│                      `AuthorizedAction<PendingApproval>`                                         │
│                             │                                                                    │
│                             ▼ `ApprovalEngine::resolve()` (if required)                          │
│                      `AuthorizedAction<Ready>`                                                   │
│                             │                                                                    │
│                             ▼ `CredentialBroker::acquire_lease()`                                │
│                      `AuthorizedAction<WithCredential>`                                          │
│                             │                                                                    │
│                             ▼ `NativeConnector::execute()` / `Dispatcher::dispatch()`            │
│                      `ExecutionRecord`                                                           │
│                             │                                                                    │
│                             ▼ `ReceiptEngine::assemble_and_sign()`                               │
│                      `SignedActionReceipt` (DSSE) ──► `Ledger::append()`                         │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Core Rust Trait Definitions

```rust
// 1. Policy Decision Point Contract
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        request: &NormalizedRequest,
        context: &EvaluationContext,
    ) -> Result<PolicyDecision, PolicyError>;
}

// 2. Native Connector Contract
#[async_trait]
pub trait NativeConnector: Send + Sync {
    fn namespace(&self) -> &'static str;
    fn canonicalize(&self, tool_name: &str, raw_args: &serde_json::Value) -> Result<CanonicalRequest, ConnectorError>;
    async fn execute(
        &self,
        request: &CanonicalRequest,
        lease: Option<&CredentialLease>,
    ) -> Result<ExecutionOutput, ConnectorError>;
}

// 3. Credential Broker Contract
#[async_trait]
pub trait CredentialBroker: Send + Sync {
    async fn acquire_lease(&self, provider: &str, scope: &str) -> Result<CredentialLease, CredentialError>;
}

// 4. Ledger Persistence Contract
#[async_trait]
pub trait Ledger: Send + Sync {
    async fn append_receipt(&self, receipt: &SignedActionReceipt) -> Result<LedgerEntry, LedgerError>;
    async fn verify_chain(&self) -> Result<VerificationReport, LedgerError>;
}
```

---

## 4. Frozen Security Invariants

The 18 Security Invariants (SIs) from `A004-security-invariants.md` are frozen as mandatory, automated build criteria:

| Invariant ID | Formal Name | Mandatory Enforcement Rule |
| :--- | :--- | :--- |
| **`SI-001`** | Zero Ambient Agent Secrets | Agent process environment, memory, and stdio contains zero target secrets. |
| **`SI-002`** | Authorization Precedes Execution | No I/O or connector execution is physically possible without an `AuthorizedAction<Ready>` token. |
| **`SI-003`** | Default Deny Enforcement | Any action not explicitly matched by a Cedar `permit` rule evaluates to `DENY`. |
| **`SI-004`** | Approval Bound to ActionHash | TTY approvals are cryptographically bound to $\text{SHA-256}(\text{JCS}(\text{parameters}))$. |
| **`SI-005`** | Canonical Representation Equivalence| Evaluated canonical request struct $\equiv$ executed request struct (zero re-parsing). |
| **`SI-006`** | Single-Action Credential Lease Scope| Leases are affine single-use tokens; secrets are zeroized in memory immediately on drop. |
| **`SI-007`** | Zero Secrets in Persistence | Raw credentials never enter the SQLite ledger, state databases, or config files. |
| **`SI-008`** | Zero Secrets in Observability | Secrets are redacted from all JSON-RPC errors, stdout/stderr streams, and DSSE receipts. |
| **`SI-009`** | Immutable Ledger Hash-Chain | Every receipt block links to predecessor via $\text{SHA-256}(\text{Seq} \mathbin{\Vert} \text{PrevHash} \mathbin{\Vert} \text{Envelope})$. |
| **`SI-010`** | Policy Version Binding | Receipt attestation binds the cryptographic SHA-256 digest of the Cedar policy set. |
| **`SI-011`** | Unambiguous Tool Namespacing | Tools are namespaced as `<server>.<tool>`; dynamic tool renaming is forbidden. |
| **`SI-012`** | Canonical Resource Paths | File paths are resolved to physical targets via `openat` (`O_NOFOLLOW` / `O_RESOLVE_BENEATH`). |
| **`SI-013`** | Domain AST Normalization | SQL queries and complex inputs are parsed into canonical ASTs before Cedar evaluation. |
| **`SI-014`** | Universal Fail-Closed Behavior | Any parsing error, timeout, or missing key immediately aborts execution with `-3200x` error. |
| **`SI-015`** | Epistemic Receipt Segregation | Receipts distinguish Relay assertions, observations, and external API claims. |
| **`SI-016`** | Replay Prevention (Nonces) | Every action requires a unique UUIDv7 nonce; replayed frames are rejected. |
| **`SI-017`** | Memory Zeroization & mlock | `SecretBuffer` uses `ZeroizeOnDrop` and `libc::mlock` to prevent swap-to-disk. |
| **`SI-018`** | Subprocess Egress Token Auth | Loopback proxy requires an ephemeral 128-bit `Proxy-Authorization` bearer token. |

---

## 5. Frozen Persistence Model & Schemas

### 5.1 Directory Layout (`~/.config/relay/` and `.relay/`)
```text
~/.config/relay/
├── relay.toml                  # Configuration (0600)
└── policies/
    ├── default.cedar           # Cedar policy definitions
    └── relay_schema.cedarschema # Cedar schema definition

.relay/
├── ledger.db                   # SQLite WAL database (0600)
├── ledger.db-wal               # SQLite WAL file
└── keys/
    ├── node.pub                # Ed25519 public key (0644)
    └── node.key                # Fallback encrypted private key (0600)
```

### 5.2 Frozen SQLite Schema (`.relay/ledger.db`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS receipts (
    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    parent_receipt_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,
    tool_namespace TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    action_decision TEXT NOT NULL,
    dsse_envelope JSON NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_receipt_id ON receipts(receipt_id);
CREATE INDEX IF NOT EXISTS idx_receipts_tool ON receipts(tool_namespace, tool_name);
```

---

## 6. Frozen CLI Surface

Implemented using `clap` (derive API) in `relay-cli`:

```bash
relay [OPTIONS] <COMMAND>

COMMANDS:
  run       Wrap and govern an MCP server over stdio
            Usage: relay run [OPTIONS] -- <SERVER_COMMAND> [ARGS]...
            Options:
              --non-interactive     Fail-closed on approvals; no /dev/tty prompt
              --policy <DIR>        Path to Cedar policy directory
              --env <KEY=VAL>       Dynamic secret interpolation (e.g. DATABASE_URL=vault:pg_prod)

  policy    Validate and inspect Cedar policies
            Subcommands:
              validate              Validate syntax and type-check against schema
              test                  Run test suites against policy fixtures

  secret    Manage vaulted credentials in OS keyring
            Subcommands:
              set <KEY> <VALUE>     Store secret in OS keyring
              get <KEY>             Retrieve secret metadata (masked value)
              list                  List configured secret keys
              delete <KEY>          Purge secret from keyring

  verify    Verify cryptographic integrity of local ledger
            Usage: relay verify [OPTIONS]
            Options:
              --from <SEQ>          Start verification from sequence number
              --pubkey <PATH>       Path to Ed25519 public key for verification

  receipt   Query action receipts from ledger
            Subcommands:
              get <RECEIPT_ID>      Fetch receipt by UUIDv7 or hash
              list                  List receipts with pagination and filters

  doctor    Diagnose environment, keyring access, keys, and permissions
            Usage: relay doctor
```

---

## 7. Frozen Rust Dependency Set

All dependencies are locked to audited, permissive licenses (MIT / Apache-2.0 / BSD-3) as specified in `A008`:

```toml
[workspace.dependencies]
# Async Runtime & Syscalls
tokio = { version = "1.38", features = ["rt-multi-thread", "macros", "io-std", "process", "sync", "time", "net", "fs"] }
rustix = { version = "0.38", features = ["fs", "process", "net"] }
libc = "0.2"

# Cedar Policy Engine
cedar-policy = "3.2"

# Serialization & Canonicalization
serde = { version = "1.0", features = ["derive", "alloc"] }
serde_json = { version = "1.0", features = ["alloc", "raw_value", "preserve_order"] }
serde_jcs = "0.1"

# Cryptography & Security
ed25519-dalek = { version = "2.1", features = ["rand_core", "serde"] }
sha2 = "0.10"
zeroize = { version = "1.8", features = ["derive"] }
keyring = { version = "3.0", features = ["apple-native", "sync-secret-service"] }
base64 = "0.22"

# Persistence & Storage
rusqlite = { version = "0.31", features = ["bundled", "modern_sqlite"] }

# Native Networking & Connectors
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
hyper = { version = "1.4", features = ["full"] }
http-body-util = "0.1"
sqlparser = "0.47"

# CLI & Ergonomics
clap = { version = "4.5", features = ["derive", "env"] }
uuid = { version = "1.9", features = ["v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
```

---

## 8. Vertical Implementation Milestones

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VERTICAL IMPLEMENTATION PLAN                                   │
├─────────┬──────────────────────────┬─────────────────────────────────────────────────────────────┤
│ Step    │ Milestone ID & Target    │ Deliverables & Test Gate                                    │
├─────────┼──────────────────────────┼─────────────────────────────────────────────────────────────┤
│ 1       │ **B001: Foundation**     │ Cargo workspace, CI scripts, `relay-core` domain primitives. │
│ 2       │ **B002: MCP Gateway**    │ Stdio JSON-RPC parser, 4MB limiter, subprocess runner.      │
│ 3       │ **B003: Canonicalization**│ RFC 8785 JCS, path resolver (`openat`), SQL AST parser.     │
│ 4       │ **B004: Cedar PEP**      │ In-process Cedar engine, schema binding, default-deny tests.│
│ 5       │ **B005: CredentialBroker**│ OS Keyring integration, `SecretBuffer`, memory `mlock`.     │
│ 6       │ **B006: Native Connectors**│ In-process GitHub (`reqwest`), Postgres, Filesystem tools. │
│ 7       │ **B007: Egress Proxy**   │ Local loopback proxy (`127.0.0.1:0`) with token auth.      │
│ 8       │ **B008: TTY Approval**   │ Interactive `/dev/tty` prompt with parameter hash binding.  │
│ 9       │ **B009: Receipt Engine** │ in-toto v1.0 Statement + DSSE RFC 9598 Ed25519 signer.     │
│ 10      │ **B010: SQLite Ledger**  │ WAL SQLite DB, hash-chain append, `relay verify` command.   │
│ 11      │ **B011: Golden Path**    │ End-to-end integration test (Claude Desktop $\to$ GitHub).  │
│ 12      │ **B012: Adversarial Suite**│ Replay attacks, symlink races, ReDoS, memory dump tests.   │
└─────────┴──────────────────────────┴─────────────────────────────────────────────────────────────┘
```

---

## 9. Definition of Done (DoD)

The Relay MVP implementation is complete and certified for release **if and only if** all eleven criteria are met:

1. **Compilation & Packaging:** `cargo build --release` produces a single, statically linked binary (`relay`) with zero runtime warnings (`#![deny(warnings)]`).
2. **Deterministic Test Suite:** 100% of unit and integration tests pass consistently across Tier-1 platforms (Linux x86_64, Linux aarch64, macOS Apple Silicon).
3. **Security Invariants Verified:** Automated tests prove all 18 Security Invariants (`SI-001` through `SI-018`).
4. **Zero Credential Leakage:** Memory inspection (`/proc/$PID/mem`), environment variable dumps, and debug logs confirm zero raw credentials in agent or child subprocess memory.
5. **Golden Path Operational:** Transparent execution of `relay run -- <mcp-server>` intercepting tool calls, evaluating Cedar, injecting credentials, and returning responses to Claude Desktop.
6. **Denied Actions Halted:** Cedar `forbid` rules or unmatched actions return `-32003 Action Forbidden` with zero downstream I/O dispatched.
7. **Approval Binding Verified:** Parameter mutation between TTY approval and dispatch triggers an immediate signature mismatch rejection.
8. **Receipt Verification:** `relay verify` mathematically validates DSSE signatures and SHA-256 hash chains over test ledgers.
9. **Tampering Detection:** Flipping a single bit in `.relay/ledger.db` causes `relay verify` to identify the exact corrupted sequence number.
10. **Crash Consistency:** Simulating `kill -9` during execution leaves SQLite in a valid WAL state without silent record corruption.
11. **Documented Host Sandbox Limitation:** CLI help and docs explicitly state that unconfined host bash execution requires an OS container/microVM boundary for complete network egress isolation.

---

## 10. Explicitly Frozen Non-Goals

The following features are **permanently out of scope** for the MVP:

* ❌ **No Multi-Tenant Cloud SaaS:** No hosted web dashboard, no multi-tenant database clusters.
* ❌ **No Enterprise Identity Federation:** No Okta/Entra SCIM user synchronization or SAML SSO.
* ❌ **No Bespoke Policy Language:** AWS Cedar is the exclusive policy engine; no custom DSL.
* ❌ **No Probabilistic LLM Firewalls:** No natural language prompt injection classifiers or toxicity filters.
* ❌ **No Generic Telemetry Platform:** No prompt tracing, token cost accounting, or eval scoring dashboards.
* ❌ **No Eve Framework Dependency in Core:** The Relay PEP core is 100% framework-agnostic.
* ❌ **No Distributed Asynchronous HITL:** No multi-party WebAuthn / Slack / Teams approval routing in MVP.
* ❌ **No Kubernetes Admission Webhooks:** No K8s mutating controllers or CRD operators.
* ❌ **No Cloud Control Plane Phoning:** Zero outbound telemetry or cloud dependencies.

---

## 11. Architecture Change Protocol

If an implementation engineer discovers that an architectural decision is flawed or infeasible, **silent in-code redesign is strictly forbidden**.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ARCHITECTURE CHANGE WORKFLOW                                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

   1. Discovery of Defect / Blocker during Milestone Implementation
                           │
                           ▼
   2. Draft Architecture Decision Record (ADR) in `docs/architecture/adr/ADR-xxx.md`
      • Problem Statement & Root Cause
      • Affected Security Invariants (SI-xxx)
      • Proposed Change & Alternative Options Considered
                           │
                           ▼
   3. Architectural Review & Sign-Off by Lead Architect
                           │
                           ▼
   4. Update Affected Architecture Specs (`A001`–`A010`) & Test Plans
                           │
                           ▼
   5. Update Test Cases & Resume Implementation
```

---

## Final Statement

> **The architecture is frozen for implementation unless an explicit architectural change is recorded and reviewed.**
