# A009: Adversarial Architecture Review & Threat Verification Report

**Document ID:** `A009-adversarial-review`  
**Date:** September 2026  
**Status:** Approved Canonical Review  
**Target System:** Relay MVP (Local-First Zero-Trust MCP Security Gateway & Credential Broker)  
**Author:** Adversarial Systems & Security Architect  
**Corpus Under Review:** `00-research-synthesis`, `A001`–`A008`, `R001`–`R015`

---

## Executive Summary

This document presents the definitive adversarial review of the **Relay MVP** architectural specification. The objective of this review is not to validate design intentions, but to rigorously test whether the architecture is safe, internally consistent, practically implementable, resilient against adversarial compromise, and operationally viable for developers.

Every subsystem—including Policy Enforcement (Cedar PDP), JSON Canonicalization (RFC 8785 JCS), Credential Isolation (Keyring, `zeroize`, `mlock`), Process Sandboxing, SQLite Hash-Chain Auditing, and Terminal I/O Multiplexing—was subjected to adversarial red-teaming, race-condition analysis, and protocol boundary stress tests.

### Review Verdict Summary

**VERDICT: BUILD WITH CONDITIONS**

The core foundation—a single-binary, local-first Rust security gateway utilizing AWS Cedar for authorization, OS Keyring for root secret storage, pure in-tree MCP protocol handling, and append-only SQLite DSSE action receipts—is **fundamentally sound and superior to existing brittle proxy designs**. 

However, this review identifies **3 High-Severity Architectural Gaps** and **5 Medium-Severity Edge Cases** that must be conditioned into the MVP implementation to prevent TOCTOU bypasses, loopback proxy token impersonation on macOS, and approval fatigue failure modes.

---

## Table of Contents

1. [Adversarial Review Dimensions](#1-adversarial-review-dimensions)
2. [Critical Findings (Blockers)](#2-critical-findings-blockers)
3. [High Findings (Pre-Release Conditions)](#3-high-findings-pre-release-conditions)
4. [Medium Findings (Important Non-Blockers)](#4-medium-findings-important-non-blockers)
5. [Low Findings (Hardening Opportunities)](#5-low-findings-hardening-opportunities)
6. [Detailed Finding Matrix](#6-detailed-finding-matrix)
7. [Final Verdict & Required Implementation Conditions](#7-final-verdict--required-implementation-conditions)

---

## 1. Adversarial Review Dimensions

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                ADVERSARIAL EVALUATION SURFACE                                    │
├───────────────────┬──────────────────────────────────────────────────────────────────────────────┤
│ Dimension         │ Specific Attack Vectors & Failure Modes Probed                               │
├───────────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ 1. Security       │ Policy evasion, unicode canonicalization confusion, symlink TOCTOU, memory   │
│                   │ leakage via swap/dumps, loopback proxy hijacking, ambient env leakage.        │
├───────────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ 2. Architecture   │ Native vs. wrapped MCP execution impedance, single-writer queue bottlenecks, │
│                   │ async cancellation state corruption, layer inversion.                       │
├───────────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ 3. Operational    │ Process crash mid-mutation, SQLite WAL lock contention, headless CI failure, │
│                   │ orphaned child process groups, POSIX signal handling races.                  │
├───────────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ 4. Protocol       │ MCP schema drift, duplicate JSON key parsing differentials, oversized frames,│
│                   │ tool namespace collisions, stdio framing desynchronization.                  │
├───────────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ 5. Cryptography   │ DSSE Pre-Authentication Encoding (PAE) canonicalization, hash-chain gaps on  │
│                   │ crash rollback, Ed25519 signing key lifecycle, replay vulnerabilities.       │
├───────────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ 6. Developer Exp. │ Approval fatigue, `/dev/tty` blocking in unattended pipelines, log noise    │
│                   │ breaking agent JSON parsers, configuration overhead.                         │
└───────────────────┴──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Critical Findings (Blockers)

*No Critical (Architecture-Breaking / Full Redesign) flaws were discovered.* The foundational separation of concerns (Pure Domain $\to$ Canonical Normalizer $\to$ In-Memory Cedar PDP $\to$ Native Connectors $\to$ Append-Only Ledger) is logically cohesive and mathematically sound.

---

## 3. High Findings (Pre-Release Conditions)

### `FINDING-HIGH-01`: Loopback Proxy Client Identity Impersonation on macOS
* **Severity:** **HIGH**
* **Affected Component:** `relay-credentials::proxy` (Loopback HTTP Egress Proxy)
* **Problem:**  
  On Linux, the loopback proxy on `127.0.0.1:<PORT>` can verify the PID/UID of the connecting client using `SO_PEERCRED` / `getsockopt`. On macOS (BSD socket layer), `SO_PEERCRED` does not exist for TCP loopback sockets (`LOCAL_PEERPID` is supported **only** on Unix Domain Sockets). Consequently, any unprivileged local process running under the same user account on macOS could establish a TCP connection to `127.0.0.1:<PORT>` and obtain JIT-injected Authorization bearer headers without authorization.
* **Attack Scenario:**  
  A developer runs a malicious npm package in a separate terminal. The package scans local loopback ports, discovers Relay's ephemeral proxy, sends an outbound request to `api.github.com`, and Relay unwittingly injects the user's vaulted GitHub PAT into the request.
* **Recommendation:**  
  1. On macOS/Linux, prefer **Unix Domain Sockets (UDS)** for child MCP proxy communication where `LOCAL_PEERPID` / `SO_PEERCRED` is guaranteed.
  2. For tools that require standard TCP `HTTP_PROXY`, generate an **ephemeral 128-bit Proxy-Authorization Bearer Token** at spawn time, passed exclusively to the child via private pipe/environment (`RELAY_PROXY_AUTH`), and require the proxy to validate this token on every request before injecting target secrets.
* **Milestone:** **MVP Mandatory Condition**

---

### `FINDING-HIGH-02`: Filesystem Symlink TOCTOU Between Cedar PDP and Connector Dispatch
* **Severity:** **HIGH**
* **Affected Component:** `relay-canonical::path` and `relay-connectors::filesystem`
* **Problem:**  
  The canonicalizer resolves symlinks (e.g. `/workspace/link` $\to$ `/workspace/data/file.txt`) and passes the canonical path to Cedar, which permits access. However, between the time Cedar evaluates the path and the native filesystem connector opens the file (`std::fs::File::open`), a concurrent process or malicious agent child can swap the symlink target to `/etc/shadow`.
* **Attack Scenario:**  
  An agent issues `fs.read_file(path: "/workspace/link")`. Relay normalizes `/workspace/link` to `/workspace/file`, Cedar approves it. Before `relay-connectors` executes `File::open("/workspace/link")`, a background thread swaps `/workspace/link` $\to$ `/etc/shadow`. Relay opens and reads `/etc/shadow`.
* **Recommendation:**  
  The filesystem connector must **never** reopen the user-supplied string path after normalization. It must open files using **file-descriptor-relative syscalls (`openat` with `O_NOFOLLOW` and `O_RESOLVE_BENEATH` / `rustix::fs::openat`)** rooted at the verified workspace directory, or re-verify file inode and device numbers (`fstat`) against the pre-authorization snapshot.
* **Milestone:** **MVP Mandatory Condition**

---

### `FINDING-HIGH-03`: Wrapped Subprocess Environment vs. Target Credential Chicken-and-Egg Impedance
* **Severity:** **HIGH**
* **Affected Component:** `relay-cli::run` and `relay-mcp::subprocess`
* **Problem:**  
  `A001` and `A007` specify that `relay run -- <command>` wraps arbitrary third-party MCP servers (e.g. `npx @modelcontextprotocol/server-postgres`) while strictly executing `env_clear()` to eliminate ambient credentials. However, third-party MCP servers like `server-postgres` require database connection strings or passwords **at startup** via command line args or `DATABASE_URL`. If Relay clears the environment and doesn't know how to inject credentials into an arbitrary third-party process CLI, the child process crashes immediately.
* **Attack/Failure Scenario:**  
  A developer runs `relay run -- npx -y @modelcontextprotocol/server-postgres`. The server exits immediately with `Error: DATABASE_URL is required`. If the developer passes `postgresql://user:pass@localhost/db` on the CLI, `ps aux` exposes the secret, violating Invariant `SI-004`.
* **Recommendation:**  
  Explicitly formalize the two-tier MCP execution model in the architecture:
  1. **Tier 1 (Native Relay Connectors):** GitHub, Postgres, Filesystem connectors execute *inside* Relay's binary. Secrets are fetched JIT from Keyring into zeroized memory only for the duration of the SQL/HTTP call. (Primary MVP model).
  2. **Tier 2 (Wrapped Subprocess with Loopback Proxy):** For HTTP/REST MCP servers, Relay injects `HTTP_PROXY=http://127.0.0.1:<PORT>` and scrubs ambient keys.
  3. **Tier 3 (Subprocess Config Substitution):** For third-party MCP servers requiring DB strings, Relay supports dynamic templating (e.g. `relay run --env DATABASE_URL=vault:pg_prod -- ...`) where Relay resolves the vaulted secret and injects it into the child environment *only* if the user explicitly authorizes that server's blast radius.
* **Milestone:** **MVP Mandatory Condition**

---

## 4. Medium Findings (Important Non-Blockers)

### `FINDING-MED-01`: Approval Fatigue via Unbounded Session Authorization Prompts
* **Severity:** **MEDIUM**
* **Affected Component:** `relay-cli::tty` (Interactive Approval Engine)
* **Problem:**  
  In `A007`, the interactive prompt offers `[a] Approve all for session`. This option is dangerously broad: approving all `postgres.execute` for the session authorizes subsequent destructive queries (`DROP TABLE`, `DELETE FROM users`) under the same blanket permission. Conversely, prompting on every single `SELECT` causes severe approval fatigue, leading developers to blindly hit `y`.
* **Attack Scenario:**  
  The developer presses `a` on an innocent `UPDATE` query during an interactive session. The agent later hallucinates or is prompt-injected to execute `DROP TABLE audit_log`. Because the session is authorized, Relay dispatches the query without prompting.
* **Recommendation:**  
  Scope the `[a]` session approval to **(Tool + Resource + Operation Family)** rather than the entire tool. For example, `Approve all SELECT on billing_db for session`, while any `DROP`, `ALTER`, or `TRUNCATE` continues to force an explicit single-use prompt regardless of prior session approvals.
* **Milestone:** **MVP Target**

---

### `FINDING-MED-02`: Asymmetric Ledger Hash-Chain Discontinuity on Process SIGKILL
* **Severity:** **MEDIUM**
* **Affected Component:** `relay-ledger::wal` and `relay-receipts`
* **Problem:**  
  When an action executes successfully against an external API (e.g., GitHub Issue created), Relay signs an Action Receipt and dispatches an `AppendReceiptCommand` to the SQLite writer thread. If the host machine suffers power loss or `SIGKILL` before the SQLite WAL checkpoint fsyncs, the external state was mutated, but the ledger entry is lost on rollback. On restart, the sequence index resumes from $N-1$, leaving the external mutation unrecorded.
* **Attack/Failure Scenario:**  
  An agent triggers an authorized payment or infrastructure deletion. The binary crashes immediately after HTTP 200 response. The local ledger contains no receipt of the transaction, creating an audit discrepancy.
* **Recommendation:**  
  Implement a **Two-Phase Intent Logging Protocol** in the ledger:
  1. Record `STAGE_INTENT` (ActionHash, Sequence $N$, Status: `IN_FLIGHT`) before dispatching to target connector.
  2. Record `STAGE_RECEIPT` (DSSE Envelope, Status: `COMPLETED` / `FAILED`) upon return.
  3. On startup recovery, any dangling `IN_FLIGHT` intents are flagged as `UNRESOLVED_CRASH` in the ledger.
* **Milestone:** **Post-MVP Hardening (Acceptable for MVP with Synchronous WAL)**

---

### `FINDING-MED-03`: Headless CI Keyring Failure Without D-Bus Session
* **Severity:** **MEDIUM**
* **Affected Component:** `relay-credentials::keyring`
* **Problem:**  
  On standard Linux CI runners (e.g., GitHub Actions Ubuntu images or Docker containers), the Secret Service D-Bus daemon is absent. If Relay attempts to call `keyring::Entry::get_password()`, it receives a D-Bus timeout error (taking up to 30 seconds to fail).
* **Failure Scenario:**  
  A developer integrates `relay run --strict` into their GitHub Actions CI pipeline. Every test run hangs for 30 seconds before crashing with `KeyringUnavailable`.
* **Recommendation:**  
  Add an immediate, zero-latency environment check: if `RELAY_KEYRING_FALLBACK=file` or `CI=true` or `DBUS_SESSION_BUS_ADDRESS` is missing, Relay immediately bypasses the D-Bus probe and uses the memory/Argon2id file key vault without hanging.
* **Milestone:** **MVP Target**

---

### `FINDING-MED-04`: DSSE In-Toto Statement JSON Whitespace Ambiguity
* **Severity:** **MEDIUM**
* **Affected Component:** `relay-receipts::dsse`
* **Problem:**  
  DSSE (RFC 9598) computes the signature over `PAE(payloadType, payload)`. If `payload` is the JSON serialization of an in-toto Statement, standard `serde_json::to_vec()` does not guarantee deterministic key ordering or number representation across different compiler versions or external verifiers.
* **Attack Scenario:**  
  A third-party auditor decodes the in-toto Statement from the receipt, re-serializes it using Python or Go, and verifies the Ed25519 signature. The verification fails due to JSON whitespace/key-ordering discrepancies, falsely indicating tampering.
* **Recommendation:**  
  Formally specify in `relay-receipts` that the in-toto Statement JSON payload MUST be canonicalized using **RFC 8785 (JCS)** *before* passing the byte array into the DSSE `PAE` builder and *before* base64-encoding into the envelope.
* **Milestone:** **MVP Target**

---

### `FINDING-MED-05`: MCP Dynamic Tool Registration / Schema Mutation Denial of Service
* **Severity:** **MEDIUM**
* **Affected Component:** `relay-mcp::gateway`
* **Problem:**  
  Invariant `SI-006` mandates that `SchemaSetHash` is pinned during initial handshake, and any runtime modification of tool definitions immediately halts the session. While secure against schema poisoning, certain compliant MCP servers dynamically register tools as context changes (e.g., loading a new database schema). Relay will abort these valid sessions.
* **Failure Scenario:**  
  A user connects Relay to an MCP server that refreshes its tool catalog after the user opens a new project workspace. Relay detects the schema set change and abruptly terminates the connection.
* **Recommendation:**  
  Allow dynamic schema updates **only if** the updated `tools/list` frame triggers an explicit re-authorization and re-hashing cycle in the Policy Decision Point, rather than an unrecoverable fatal crash.
* **Milestone:** **Post-MVP**

---

## 5. Low Findings (Hardening Opportunities)

### `FINDING-LOW-01`: Regex Secret Redaction ReDoS Risk
* **Severity:** **LOW**
* **Affected Component:** `relay-cli::redaction`
* **Problem:**  
  Custom user-supplied regexes via `--redact-patterns` could contain pathological catastrophic backtracking patterns, causing high CPU consumption during log filtering.
* **Recommendation:**  
  The `regex` crate in Rust is linear-time by design (DFA/NFA engine without backtracking), mitigating classic ReDoS. However, enforce a maximum regex size limit ($\le 10\text{ KB}$) and compile regexes once at startup.
* **Milestone:** **MVP Hardening**

---

### `FINDING-LOW-02`: SQLite WAL Auto-Checkpoint Starvation Under Continuous Load
* **Severity:** **LOW**
* **Affected Component:** `relay-ledger::sqlite`
* **Problem:**  
  If multiple agent threads generate a continuous, uninterrupted stream of read transactions, SQLite WAL auto-checkpointing may be indefinitely deferred, causing `ledger.db-wal` to grow unbounded on disk.
* **Recommendation:**  
  Configure the background storage actor thread to periodically invoke `PRAGMA wal_checkpoint(PASSIVE);` or `TRUNCATE` during idle frames.
* **Milestone:** **MVP Hardening**

---

## 6. Detailed Finding Matrix

| Finding ID | Severity | Category | Target Component | Description | Milestone |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`HIGH-01`** | **HIGH** | Security | `relay-credentials::proxy` | Loopback proxy lacks client auth on macOS TCP sockets. | **MVP Mandatory** |
| **`HIGH-02`** | **HIGH** | Security | `relay-connectors::filesystem`| Filesystem symlink TOCTOU between Cedar check and open. | **MVP Mandatory** |
| **`HIGH-03`** | **HIGH** | Architecture | `relay-cli::run` | Wrapped subprocess ambient credential chicken-and-egg gap. | **MVP Mandatory** |
| **`MED-01`** | **MEDIUM** | UX / Security | `relay-cli::tty` | "Approve for session" option is too broad (fatigue/risk). | **MVP Target** |
| **`MED-02`** | **MEDIUM** | Reliability | `relay-ledger::wal` | State mutation persists if crash occurs before WAL fsync. | **Post-MVP** |
| **`MED-03`** | **MEDIUM** | Operational | `relay-credentials::keyring`| 30s D-Bus timeout on headless Linux CI environments. | **MVP Target** |
| **`MED-04`** | **MEDIUM** | Cryptography | `relay-receipts::dsse` | in-toto Statement JSON needs strict JCS canonicalization. | **MVP Target** |
| **`MED-05`** | **MEDIUM** | Protocol | `relay-mcp::gateway` | Strict schema pinning breaks valid dynamic MCP servers. | **Post-MVP** |
| **`LOW-01`** | **LOW** | Performance | `relay-cli::redaction` | Potential CPU overhead with complex user regexes. | **MVP Hardening** |
| **`LOW-02`** | **LOW** | Operational | `relay-ledger::sqlite` | WAL growth under sustained read locks. | **MVP Hardening** |

---

## 7. Final Verdict & Required Implementation Conditions

### Final Verdict: **`BUILD WITH CONDITIONS`**

### Rationale for Verdict
The architectural design specified across `A001` through `A008` is coherent, rigorous, and uniquely addresses the foundational vulnerabilities of AI agent tool execution. The formal division between pure domain logic, deterministic canonical normalization, memory-isolated credential leasing, and append-only cryptographic attestation provides a level of security assurance absent in existing market alternatives.

The identified risks do not require a structural redesign. They are edge cases that must be explicitly resolved during implementation.

### Minimum Required Implementation Conditions

Before tagging `v0.1.0-alpha`, the engineering team must incorporate the following conditions into the codebase:

1. **Proxy Authentication Token (`HIGH-01`):**  
   The loopback HTTP proxy must require a 128-bit ephemeral `Proxy-Authorization: Bearer <ephemeral_token>` header on all requests, injected exclusively into the child process environment, preventing unauthorized local process access on macOS.
2. **Atomic Inode / `openat` Resolution (`HIGH-02`):**  
   The native filesystem connector must open files using directory-relative descriptor syscalls (`openat` with `O_NOFOLLOW` / `O_RESOLVE_BENEATH`), eliminating symlink race conditions.
3. **Formalized Connector Execution Tiers (`HIGH-03`):**  
   The MVP documentation and CLI must clearly designate **Native In-Binary Connectors (Postgres, GitHub, FS)** as the primary zero-ambient-secret execution path, while providing structured `--env` templating for legacy wrapped MCP subprocesses.
4. **Fine-Grained Session Approval Scoping (`MED-01`):**  
   Session approval caches must bind strictly to `(ToolName, ResourceNamespace, StatementType)` and exclude destructive operations (`DROP`, `DELETE`, `ALTER`) from automatic replay.
5. **Deterministic JCS DSSE Encoding (`MED-04`):**  
   All in-toto Statement payloads inside DSSE envelopes must pass through RFC 8785 JSON Canonicalization Scheme (JCS) before Pre-Authentication Encoding (PAE) and signing.
6. **Headless Keyring Fast-Fail (`MED-03`):**  
   Detect CI/headless Linux environments instantly and fallback to memory/file vaults without blocking on D-Bus connection timeouts.

---
*End of Adversarial Review.*
