# A005: Relay MVP Verification & Testing Strategy

**Document ID:** `A005-test-strategy`  
**Date:** September 2026  
**Status:** Approved Verification Specification  
**Target System:** Relay MVP (Local-First Zero-Trust MCP Security Gateway & Credential Broker)  
**Author:** Verification & Security Architect  
**Corpus Dependencies:** `A001-system-architecture`, `A002-domain-model`, `R014-mvp-definition`, `R015-build-gate`, `00-research-synthesis`, `R005` (Threat Model), `R009` (Trust Boundaries), `R010` (JIT Credentials), `R011` (Action Receipts), `R012` (MCP Boundary)

---

## Executive Summary

This document specifies the comprehensive verification and testing strategy for the **Relay MVP**. 

In conventional application development, test suites prioritize line and branch coverage. For Relay—a zero-trust security control plane—code coverage is a secondary metric. **The primary objective of this verification strategy is proving that Relay's cryptographic, authorization, credential isolation, and behavioral invariants hold under normal, malformed, adversarial, and systemic failure conditions.**

### The Verification Axiom
> **A test suite does not merely verify that authorized actions succeed; it proves that unauthorized, ambiguous, replayed, tampered, or resource-violating actions are deterministically prevented from mutating state or leaking credentials, and that every state transition generates non-repudiable audit evidence.**

---

## Table of Contents

1. [Test Hierarchy & Taxonomy](#1-test-hierarchy--taxonomy)
2. [The Canonical Golden Path Test](#2-the-canonical-golden-path-test)
3. [Adversarial Security Test Matrix](#3-adversarial-security-test-matrix)
4. [Canonicalization & Normalization Property Tests](#4-canonicalization--normalization-property-tests)
5. [Credential Isolation & Memory Security Tests](#5-credential-isolation--memory-security-tests)
6. [Cryptographic & Ledger Integrity Tests](#6-cryptographic--ledger-integrity-tests)
7. [Failure, Fault Injection & Crash Recovery Tests](#7-failure-fault-injection--crash-recovery-tests)
8. [Fuzzing Strategy & Corpus Management](#8-fuzzing-strategy--corpus-management)
9. [Regression Philosophy & Vulnerability Lifecycle](#9-regression-philosophy--vulnerability-lifecycle)
10. [Release Quality & Security Gates](#10-release-quality--security-gates)
11. [Test Observability & Secret Scrubbing](#11-test-observability--secret-scrubbing)
12. [Synthesis & Summary Tables](#12-synthesis--summary-tables)

---

## 1. Test Hierarchy & Taxonomy

Relay organizes verification across fourteen distinct test layers, each enforcing a specific operational or security boundary:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    RELAY TEST PYRAMID & HIERARCHY                                │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│  [ LAYER 14: FUZZ TESTS ]                 cargo-fuzz / libFuzzer on parsers, JCS, framing        │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 13: ADVERSARIAL GAUNTLET ]       26 real-world exploit simulations (Prompt inj, TOCTOU) │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 12: END-TO-END (E2E) TESTS ]     Full stdio client-to-target live execution runs        │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 11: LEDGER INTEGRITY TESTS ]     Hash-chain verification, corruption recovery, PRAGMA   │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 10: CRYPTOGRAPHIC TESTS ]        Ed25519 DSSE envelopes, in-toto v1.0, signature checks │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 9: CREDENTIAL ISOLATION TESTS ]  `/proc` memory inspection, zeroization drop checks     │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 8: SUBPROCESS & PROXY TESTS ]    Loopback HTTP proxy, socket auth (`SO_PEERCRED`), env  │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 7: PROTOCOL INTEGRATION TESTS ]  MCP JSON-RPC 2.0 framing, `tools/list`, `tools/call`   │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 6: CONNECTOR TESTS ]             Native GitHub, PostgreSQL, Filesystem mock drivers     │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 5: CEDAR POLICY SUITE TESTS ]    Deterministic ABAC decision tests against `.cedar`     │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 4: CANONICALIZATION TESTS ]      RFC 8785 JCS, SQL AST, path resolving, unicode NFC    │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 3: PARSER TESTS ]                Malformed JSON, oversized frames, AST edge cases       │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 2: PROPERTY-BASED TESTS ]        `proptest` invariants (roundtrips, non-collisions)     │
│  ──────────────────────────────────────────────────────────────────────────────────────────────  │
│  [ LAYER 1: UNIT TESTS ]                  Pure deterministic in-memory struct logic              │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Layer Definition Table

| Level | Scope & Boundary | Execution Time | Tools / Crates | Target Invariant |
| :--- | :--- | :--- | :--- | :--- |
| **1. Unit Tests** | In-memory functions, state transitions, builders, formatters. | $< 1\text{ms}$ / test | `cargo test --lib` | State machine correctness; type safety. |
| **2. Property Tests** | Invariant testing across randomized input spaces. | $10\text{ms}$ / prop | `proptest` | Mathematical symmetry, no panics, idempotent normalizers. |
| **3. Parser Tests** | Deserializers, framing limits, strict JSON syntax. | $< 1\text{ms}$ / test | `serde_json`, `sqlparser` | Rejection of malformed, duplicate-key, or oversized inputs. |
| **4. Canonicalization Tests** | RFC 8785 JCS encoding, Unicode NFC, filesystem paths. | $< 5\text{ms}$ / test | `relay-canonicalizer` | Identical inputs produce identical `ActionHash` values. |
| **5. Cedar Policy Tests** | AWS Cedar evaluation engine (`is_authorized`). | $< 2\text{ms}$ / test | `cedar-policy` | Strict default-deny; explicit policy permits/forbids. |
| **6. Connector Tests** | Native Rust connectors (GitHub, Postgres, FS). | $10\text{ms}$ / test | `wiremock`, `sqlx::test` | JIT leased credentials correctly applied to outbound calls. |
| **7. Protocol Integration** | MCP stdio JSON-RPC 2.0 handshake and dispatch. | $20\text{ms}$ / test | `tokio_test`, `assert_cmd` | Compliant tool listing, error codes, and result staging. |
| **8. Subprocess Tests** | Spawning child MCP servers with stripped `env`. | $50\text{ms}$ / test | `tokio::process` | Zero ambient environment variables leaked to child process. |
| **9. Credential Isolation** | Memory inspection, heap zeroization, `/proc` checks. | $30\text{ms}$ / test | `zeroize`, `procfs` | Plaintext secrets wiped immediately after wire dispatch. |
| **10. Cryptographic Tests** | DSSE envelope signing, in-toto statement hashes. | $< 5\text{ms}$ / test | `ed25519-dalek`, `sha2` | Non-repudiation, tamper detection, signature verification. |
| **11. Ledger Integrity** | SQLite hash-chain validation, WAL persistence. | $15\text{ms}$ / test | `rusqlite`, `tempfile` | Immutable sequence monotonicity, hash-link integrity. |
| **12. End-to-End (E2E)** | Full black-box execution: Agent CLI $\to$ Relay $\to$ Target. | $100\text{ms}$ / test | `rexpect`, `assert_cmd` | Golden path completion, valid receipts, accurate return. |
| **13. Adversarial Tests** | Simulated real-world attacks (TOCTOU, injections). | $50\text{ms}$ / test | Custom test harness | Zero privilege escalation under compromised agent runtime. |
| **14. Fuzz Tests** | Continuous coverage-guided mutation fuzzing. | Hours / Continuous | `cargo-fuzz`, `libFuzzer` | Zero memory corruption, no panics, no unhandled parser hangs. |

---

## 2. The Canonical Golden Path Test

The **Golden Path Test** (`tests/e2e/test_golden_path.rs`) is the definitive end-to-end verification baseline. It validates the full lifecycle of an authorized state-mutating tool invocation.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    GOLDEN PATH EXECUTION FLOW                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

 [ UNTRUSTED AGENT ]                                            [ RELAY TRUSTED COMPUTING BASE ]
        │
        │ 1. `tools/call` JSON-RPC (stdio)
        ▼
 ┌──────────────┐      2. UTF-8 & Frame Size Checks (< 4MB)
 │ MCP Gateway  │ ─────────────────────────────────────────────────────────┐
 └──────────────┘                                                          │
        │                                                                  ▼
        │ 3. Canonicalize Parameters (RFC 8785 JCS + Unicode NFC)   ┌──────────────┐
        └──────────────────────────────────────────────────────────►│ Canonicalizer│
                                                                    └──────┬───────┘
                                                                           │ 4. Compute `ActionHash`
                                                                           ▼
 ┌──────────────┐      5. Evaluate `is_authorized(Principal, Action, ...)`  ┌──────────────┐
 │ Cedar PDP    │ ◄──────────────────────────────────────────────────────── │ Action Model │
 └──────┬───────┘                                                           └──────────────┘
        │ 6. Returns `Decision::Allow` (Matched: "policy_allow_github_write")
        ▼
 ┌──────────────┐      7. Request Ephemeral Credential
 │ Credential   │ ◄────────────────────────────────── (Keyring: "github_pat")
 │ Broker       │ ──► Decrypts into `SecretBuffer` (ZeroizeOnDrop)
 └──────┬───────┘
        │ 8. Leased Credential injected JIT into Native Connector
        ▼
 ┌──────────────┐      9. Outbound HTTPS POST (api.github.com)
 │ GitHub Conn  │ ─────────────────────────────────────────────────────────► [ GITHUB API ]
 └──────┬───────┘                                                                  │
        │ 10. HTTP 201 Created (Payload: `{ "id": 101, "number": 42 }`)           │
        │ ◄────────────────────────────────────────────────────────────────────────┘
        ▼
 ┌──────────────┐      11. Format in-toto v1.0 Statement & Sign DSSE Envelope
 │ Signer Engine│ ──► Ed25519 Private Key Sign -> Generates `ActionReceipt`
 └──────┬───────┘
        │ 12. Write to SQLite Ledger (`ledger.db`)
        ▼
 ┌──────────────┐      13. Atomic Append & SHA-256 Hash Chain Link
 │ SQLite Ledger│ ──► `sequence_number = N+1`, `parent_hash = H(N)`
 └──────┬───────┘
        │ 14. Emit MCP JSON-RPC Result to stdio
        ▼
 [ UNTRUSTED AGENT ] (Receives `{ "content": [...], "_relay_receipt": "0x8f3b..." }`)
```

### Exact Concrete Input / Output Specifications

#### 1. Input JSON-RPC Frame (Received on stdio)
```json
{
  "jsonrpc": "2.0",
  "id": "call-001",
  "method": "tools/call",
  "params": {
    "name": "github.create_issue",
    "arguments": {
      "repository": "acme/backend",
      "title": "Fix memory leak in buffer",
      "labels": ["bug", "security"]
    }
  }
}
```

#### 2. Generated Canonical Authorization Request
```json
{
  "principal": "principal:agent:claude-code:v1.0",
  "action": "action:github.create_issue",
  "resource": "github://github.com/acme/backend",
  "session_id": "sess_01J8YV1B0Z4A8B9C0D1E2F3G4H",
  "tool": {
    "name": "github.create_issue",
    "schema_digest": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
  },
  "arguments": {
    "labels": ["bug", "security"],
    "repository": "acme/backend",
    "title": "Fix memory leak in buffer"
  },
  "environment": {
    "timestamp": "2026-09-12T23:58:00Z",
    "working_directory": "/home/user/workspace"
  }
}
```

#### 3. Resulting In-Toto v1.0 Statement (Inside DSSE Payload)
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "github://github.com/acme/backend",
      "digest": {
        "action_payload": "sha256:9f83c6f8821034f8a31e843b0e457f00d3a7e4b9d0b616a2b8e3c129486c91a7"
      }
    }
  ],
  "predicateType": "https://relay.dev/attestation/action-receipt/v1",
  "predicate": {
    "receipt_id": "rcpt_01J8YV2M4N5P6Q7R8S9T0V1W2X",
    "session_id": "sess_01J8YV1B0Z4A8B9C0D1E2F3G4H",
    "step_index": 1,
    "action_hash": "sha256:9f83c6f8821034f8a31e843b0e457f00d3a7e4b9d0b616a2b8e3c129486c91a7",
    "invocation": {
      "tool_name": "github.create_issue",
      "canonical_arguments_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "authorization": {
      "decision": "ALLOW",
      "policy_digest": "sha256:112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
      "determining_policies": ["policy_allow_github_write"],
      "evaluated_at": "2026-09-12T23:58:00.045Z"
    },
    "execution": {
      "status": "SUCCEEDED",
      "exit_code": 0,
      "duration_ms": 142,
      "output_hash": "sha256:4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123"
    }
  }
}
```

#### 4. Final stdio Response to Agent Client
```json
{
  "jsonrpc": "2.0",
  "id": "call-001",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Issue #42 created successfully: https://github.com/acme/backend/issues/42"
      }
    ],
    "_relay_receipt": {
      "receipt_id": "rcpt_01J8YV2M4N5P6Q7R8S9T0V1W2X",
      "action_hash": "sha256:9f83c6f8821034f8a31e843b0e457f00d3a7e4b9d0b616a2b8e3c129486c91a7",
      "sequence_number": 42
    }
  }
}
```

---

## 3. Adversarial Security Test Matrix

The test suite must execute the **26-Vector Adversarial Security Matrix**. Every test is configured with a deterministic adversarial setup, payload, expected behavior, and verified invariant:

| # | Attack Vector | Adversarial Test Setup | Attack Execution Payload | Expected Relay Behavior | Security Invariant Exercised |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Prompt Injection (Natural Lang Intent)** | Agent runtime context injected via RAG prompt. | `{"name": "github.delete_repo", "intent": "Helpful summary", "arguments": {"repo": "acme/core"}}` | Immediate `Decision::Deny`. Relay ignores `intent` and evaluates Cedar policy on raw parameter `repo`. | **INV-02: Non-Authoritative Intent** |
| **2** | **Malicious Parameter Mutation** | Cedar policy permits `write` only to `/workspace/tmp/*`. | `{"name": "fs.write_file", "arguments": {"path": "/etc/shadow", "content": "root::0:0:..."}}` | Policy engine returns `DENY`. Execution is halted; no file I/O attempted. | **INV-01: Deterministic ABAC** |
| **3** | **Path Traversal (`../`)** | Policy permits `/workspace/data/*`. | `{"name": "fs.read_file", "arguments": {"path": "/workspace/data/../../etc/passwd"}}` | Normalizer canonicalizes path to `/etc/passwd`. Policy evaluates `/etc/passwd`, returns `DENY`. | **INV-03: Canonical Representation** |
| **4** | **Symlink Escape** | `/workspace/data/link` created pointing to `/root/.ssh`. | `{"name": "fs.read_file", "arguments": {"path": "/workspace/data/link/id_rsa"}}` | Filesystem normalizer resolves physical symlink target, evaluates `/root/.ssh/id_rsa`, returns `DENY`. | **INV-03: Canonical Representation** |
| **5** | **SQL Injection (Classic)** | Policy permits queries matching `SELECT * FROM users WHERE id = :id`. | `{"name": "db.query", "arguments": {"sql": "SELECT * FROM users WHERE id = 1; DROP TABLE users;"}}` | SQL AST parser detects multi-statement batch; rejects execution or returns `DENY`. | **INV-03: Domain AST Normalization** |
| **6** | **SQL Semantic Ambiguity** | Policy forbids `DROP TABLE`. Attacker injects SQL comments. | `{"name": "db.query", "arguments": {"sql": "DROP/**/TABLE/**/audit_log;"}}` | Normalizer parses SQL AST, strips comments, formats canonical AST string, returns `DENY`. | **INV-03: Domain AST Normalization** |
| **7** | **Unicode Confusion (Homoglyph)** | Policy allows access to `github.com/acme/repo`. Attacker uses Cyrillic 'а' (`U+0430`). | `{"name": "github.read", "arguments": {"repo": "\u0430cme/repo"}}` | Unicode NFC normalizer decodes code points; string fails equality check against ASCII `acme/repo`, returns `DENY`. | **INV-03: Canonical Representation** |
| **8** | **Duplicate JSON Keys** | JSON parser differential attack (e.g. Go vs Rust vs Python). | `{"name": "github.read", "arguments": {"repo": "public/repo", "repo": "private/secret"}}` (Raw bytes) | Stdio JSON parser rejects frame immediately with RFC 8259 duplicate key error. No action evaluated. | **INV-03: RFC 8785 Canonicalization** |
| **9** | **Malformed JSON** | Incomplete syntax / unclosed braces. | `{"jsonrpc": "2.0", "method": "tools/call", "params": {` | Ingress parser rejects with JSON-RPC error `-32700 Parse Error`. Transport drops frame. | **INV-10: Fail-Closed Default** |
| **10** | **Oversized Frames (DoS)** | Memory exhaustion attack. | Stdio client writes a single $16\text{ MB}$ JSON frame. | Stdio reader detects frame exceeding $4\text{ MB}$ limit; discards frame immediately; emits `-32600 Invalid Request`. | **INV-08: Blast Radius & Rate Limit** |
| **11** | **Tool Spoofing / Shadowing** | Malicious 3rd-party MCP registers `read_file` to shadow native tool. | Third-party MCP server emits `tools/list` with name `"read_file"`. | Relay enforces mandatory namespacing; exposes tool as `rogue_server.read_file`. Shadowing blocked. | **INV-01: Deterministic Namespace** |
| **12** | **Runtime Schema Mutation** | MCP server changes parameter types post-initialization. | Server alters `inputSchema` for `delete_user` mid-session. | Relay validates `SchemaSetHash` pinned at startup; detects mismatch; halts session immediately. | **INV-06: Schema Pinning** |
| **13** | **Resource URI Spoofing** | Attacker passes custom protocol prefix. | `{"name": "fetch", "arguments": {"uri": "gopher://127.0.0.1:22"}}` | URI parser enforces allow-listed schemes (`https://`, `file://`, `github://`); rejects invalid URI. | **INV-03: Canonical Representation** |
| **14** | **Approval Mismatch (TOCTOU)** | User approves Action A; agent attempts to execute Action B. | Human confirms prompt for `delete_file(/tmp/a)`; agent dispatches `delete_file(/tmp/b)` with approval ID. | Relay binds approval strictly to `ActionHash(A)`. Dispatched `ActionHash(B)` fails lookup; execution rejected. | **INV-05: Anti-TOCTOU Binding** |
| **15** | **Policy Mismatch** | Agent attempts to invoke tool not permitted in Cedar. | `{"name": "aws.terminate_instance", "arguments": {"id": "i-123"}}` | Cedar returns `DENY` under default-deny rule. Zero AWS credentials fetched or leased. | **INV-01: Strict Default Deny** |
| **16** | **ActionHash Mismatch** | Attacker tampers with canonical payload between PDP and connector. | Injected fault alters in-memory arguments struct post-Cedar evaluation. | Connector re-computes `ActionHash` prior to dispatch; detects mismatch against decision; aborts execution. | **INV-05: Single-Binary Invariant** |
| **17** | **Credential Leakage in Logs** | Action executes with real secret `ghp_secret123456`. | Attacker triggers verbose debugging / tracing subscriber. | Tracing redaction layer matches regex `ghp_[A-Za-z0-9]{36}` and masks string to `ghp_***[REDACTED]***`. | **INV-04: Zero Ambient Secrets** |
| **18** | **Environment Leakage to Child** | Child MCP spawned to execute Slack message. | Child process executes `env` / `printenv` and dumps output to stdout. | Relay's `Command::spawn` explicitly cleared environment (`env_clear()`); `/proc/<pid>/environ` contains zero secrets. | **INV-04: Process Isolation** |
| **19** | **`/proc` Inspection Leakage** | Local user runs `ps aux` or reads `/proc/<pid>/cmdline`. | Attacker inspects CLI arguments of child MCP processes. | Relay never passes tokens as CLI args; communicates tokens exclusively over encrypted TLS stream or memory pipes. | **INV-04: Process Isolation** |
| **20** | **Child Process Leakage** | Malicious child MCP spawns a detached grandchild process. | Child executes `nohup sh -c 'sleep 1000' &`. | Relay manages child process groups (`setpgid`); kills process group upon turn completion or session exit. | **INV-08: Process Containment** |
| **21** | **Receipt Modification** | Attacker edits `.relay/ledger.db` to change `decision: DENY` to `ALLOW`. | Attacker writes directly to SQLite file using external sqlite3 CLI. | Ledger verification detects broken Ed25519 signature and broken SHA-256 hash chain; flags corruption. | **INV-09: Cryptographic Integrity** |
| **22** | **Ledger Hash-Chain Tampering** | Attacker deletes Row 41 in ledger and re-inserts modified record. | External process alters row in SQLite database. | Relay on startup verifies Merkle / hash-chain links ($H_N == \text{SHA256}(H_{N-1} + R_N)$); refuses startup on mismatch. | **INV-09: Cryptographic Integrity** |
| **23** | **Replay Attack** | Attacker re-submits exact identical JSON-RPC frame from 5 minutes ago. | Agent client transmits duplicate `call-001` with identical payload. | Relay validates monotonically increasing session step counter; rejects replayed nonce immediately. | **INV-05: Single-Use Execution** |
| **24** | **Concurrent Execution Race** | Two simultaneous `tools/call` frames arrive on stdio concurrently. | Agent sends two concurrent requests requiring TTY approval. | TTY handler acquires async mutex lock; renders approvals sequentially; prevents terminal interleaving. | **INV-07: Sanitized Sequential HITL** |
| **25** | **Process Crash Mid-Execution** | Target API receives call, but Relay process receives `SIGKILL`. | Test runner kills `relay` binary while `reqwest` HTTP call is in-flight. | SQLite WAL journal recovers cleanly on next launch; uncommitted receipt is rolled back; no DB corruption. | **INV-10: Fail-Closed Durability** |
| **26** | **Hardware Keyring Missing** | Keyring daemon disabled or inaccessible. | Relay attempts to fetch secret when OS Keyring returns `ServiceUnavailable`. | Relay fails closed, aborts action, logs `KeyringUnavailable` error, and writes rejection receipt. | **INV-10: Fail-Closed Default** |

---

## 4. Canonicalization & Normalization Property Tests

Property-based testing (using the `proptest` crate) verifies that canonicalization invariants hold across randomized and boundary inputs.

### Core Mathematical Properties

```rust
// 1. Idempotency Property: JCS(JCS(x)) == JCS(x)
proptest! {
    #[test]
    fn prop_jcs_idempotency(json_val in any_json_value()) {
        let canonical_1 = rfc8785_canonicalize(&json_val).unwrap();
        let parsed_1: serde_json::Value = serde_json::from_slice(&canonical_1).unwrap();
        let canonical_2 = rfc8785_canonicalize(&parsed_1).unwrap();
        prop_assert_eq!(canonical_1, canonical_2);
    }
}

// 2. Semantic Equality Equivalence: Equivalent JSON objects yield identical ActionHash
proptest! {
    #[test]
    fn prop_key_order_independence(
        k1 in "[a-z]{1,5}", v1 in "[0-9]{1,5}",
        k2 in "[a-z]{1,5}", v2 in "[0-9]{1,5}"
    ) {
        prop_assume!(k1 != k2);
        let json_a = serde_json::json!({ &k1: &v1, &k2: &v2 });
        let json_b = serde_json::json!({ &k2: &v2, &k1: &v1 });
        
        let hash_a = compute_action_hash(&json_a);
        let hash_b = compute_action_hash(&json_b);
        prop_assert_eq!(hash_a, hash_b);
    }
}

// 3. Collision Resistance: Distinct security-sensitive resources never produce identical ActionHash
proptest! {
    #[test]
    fn prop_path_distinctness(path_a in "/[a-z]{1,10}", path_b in "/[a-z]{1,10}") {
        prop_assume!(path_a != path_b);
        let hash_a = canonicalize_and_hash_path(&path_a);
        let hash_b = canonicalize_and_hash_path(&path_b);
        prop_assert_ne!(hash_a, hash_b);
    }
}

// 4. Parameter Sensitivity: Mutating a single parameter changes the ActionHash
proptest! {
    #[test]
    fn prop_parameter_mutation_changes_hash(
        base_val in any_json_object(),
        mutation_key in "[a-z]{1,8}",
        mutation_val in "[a-z0-9]{1,8}"
    ) {
        let mut modified_val = base_val.clone();
        modified_val.as_object_mut().unwrap().insert(mutation_key, serde_json::json!(mutation_val));
        
        let hash_base = compute_action_hash(&base_val);
        let hash_mod = compute_action_hash(&modified_val);
        prop_assert_ne!(hash_base, hash_mod);
    }
}
```

### Specific Normalization Edge Cases Under Test

1. **Unicode NFC Normalization:**
   - Precomposed `é` (`\u{00E9}`) and decomposed `e + ́` (`\u{0065}\u{0301}`) must normalize to identical bytes before hashing.
2. **IEEE 754 Floating-Point Numbers:**
   - `1.0`, `1.00`, `1e0`, and `1` must follow RFC 8785 §3.2.2.3 formatting (integers formatted without decimal; floats normalized without trailing zeros).
3. **Filesystem Path Aliases:**
   - `/workspace/src/../src/main.rs`, `/workspace/src/./main.rs`, and `/workspace/src/main.rs` must resolve to identical canonical paths.
4. **SQL Comment and Whitespace Stripping:**
   - `SELECT * FROM users` and `SELECT/**/\n*\tFROM   users;` must generate an identical AST digest.
5. **Git Reference Expansion:**
   - `main`, `heads/main`, and `refs/heads/main` must map to `refs/heads/main`.

---

## 5. Credential Isolation & Memory Security Tests

Credential security tests verify that target secrets exist **only** within scoped in-memory execution buffers and never leak to persistent storage, logs, child environments, or memory dumps.

### 5.1 The Memory Zeroization Test
```rust
#[test]
fn test_credential_lease_zeroizes_on_drop() {
    let raw_secret = "ghp_super_secret_token_12345";
    let mut secret_buffer = SecretBuffer::from_str(raw_secret);
    
    let memory_ptr = secret_buffer.as_ptr();
    let memory_len = secret_buffer.len();
    
    // Explicitly drop buffer
    drop(secret_buffer);
    
    // Inspect memory location (unsafe block for verification test only)
    unsafe {
        let memory_slice = std::slice::from_raw_parts(memory_ptr, memory_len);
        // Verify every byte was overwritten with 0x00
        assert!(memory_slice.iter().all(|&byte| byte == 0x00), "Memory was not zeroized on drop!");
    }
}
```

### 5.2 OS-Specific Process Verification Matrix

| OS Platform | Verifiable in Automated Tests | Method / Syscall | Unverifiable / OS Limitations |
| :--- | :--- | :--- | :--- |
| **Linux** | **YES** | Read `/proc/<child_pid>/environ` and `/proc/<child_pid>/cmdline`. Verify zero matching secret regexes. | Process memory during execution requires `ptrace` (requires `CAP_SYS_PTRACE`). |
| **macOS** | **PARTIAL** | Inspect `ps -E -p <child_pid>` output. Verify child environment is stripped. | macOS sandboxing limits `/proc` equivalents; memory zeroization verified via local pointer tests. |
| **Windows** | **PARTIAL** | Query Win32 `NtQueryInformationProcess` for ProcessParameters env block. | Kernel swap paging to `pagefile.sys` cannot be completely disabled without admin privileges. |

### 5.3 Leakage Channel Checklist (Automated Assertions)

Every test run verifies:
- [x] **Agent Environment:** `std::env::vars()` in child processes contains no secret keys.
- [x] **CLI Arguments:** `tokio::process::Command` args contain no credentials.
- [x] **Log Streams:** Capturing `tracing` log buffers contains no matches for `ghp_`, `sk-`, `AKIA`, or `Bearer`.
- [x] **Receipt Payloads:** Action receipts contain only `ActionHash` and `OutputHash`, never raw headers.
- [x] **SQLite Database:** `SELECT * FROM actions` and `SELECT * FROM receipts` contain zero plaintext secrets.
- [x] **Crash Reports:** `prctl(PR_SET_DUMPABLE, 0)` verified active on Linux.

---

## 6. Cryptographic & Ledger Integrity Tests

Cryptographic tests verify that Action Receipts are mathematically sound, tamper-evident, and form an unbroken hash chain in SQLite.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   HASH CHAIN VERIFICATION SCHEMA                                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

  Row 1 (Seq 1): Hash1 = SHA-256( GenesisHash + DSSE_Envelope_1 )
      │
      ▼
  Row 2 (Seq 2): Hash2 = SHA-256( Hash1 + DSSE_Envelope_2 )
      │
      ▼
  Row 3 (Seq 3): Hash3 = SHA-256( Hash2 + DSSE_Envelope_3 )
```

### Cryptographic Test Suite Table

| Test Identifier | Test Procedure | Injected Fault / Manipulation | Expected Assertion Outcome |
| :--- | :--- | :--- | :--- |
| `crypto::test_valid_dsse_sig` | Standard golden path execution. | None (Valid signature generated). | `ed25519::verify(public_key, envelope.payload, envelope.sig)` returns `Ok(())`. |
| `crypto::test_tampered_payload` | Intercept DSSE envelope in transit. | Mutate 1 bit in base64 in-toto payload. | Verification fails with `SignatureVerificationError: Invalid signature`. |
| `crypto::test_corrupted_key_id` | Alter `keyid` field in envelope. | Replace `keyid: "node_01"` with `"node_02"`. | Verification fails with `KeyNotFound: Unknown signing key ID`. |
| `crypto::test_policy_digest_tamper`| Modify `policy_digest` in predicate. | Replace Cedar policy hash with custom hash. | In-toto subject digest verification fails; signature check invalid. |
| `ledger::test_hash_chain_valid` | Read all $N$ rows in `ledger.db`. | None (Sequential traversal). | $\forall i \in [2..N], \text{Row}_i.\text{parent\_hash} == \text{Row}_{i-1}.\text{receipt\_hash}$. |
| `ledger::test_tampered_row` | Open SQLite via external connection. | Update `actions SET decision = 'ALLOW' WHERE id = 5`. | Ledger verification detects `receipt_hash` divergence at sequence 5. |
| `ledger::test_deleted_row` | Delete row sequence 10 from SQLite. | `DELETE FROM ledger_entries WHERE seq = 10`. | Verification detects sequence gap ($9 \to 11$) and broken hash link. |
| `ledger::test_swapped_rows` | Swap sequence numbers of rows 3 & 4. | `UPDATE ledger_entries SET seq = ...`. | Verification fails on both sequence monotonicity and SHA-256 parent links. |

---

## 7. Failure, Fault Injection & Crash Recovery Tests

Relay must behave deterministically under system faults. The test harness injects failures at every critical subsystem boundary:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   FAULT INJECTION TEST TOPOLOGY                                  │
├──────────────────────────┬─────────────────────────────┬─────────────────────────────────────────┤
│ Injected Subsystem Fault │ Simulated Failure Mechanism │ Expected Fail-Closed Behavior           │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 1. Cedar Engine Panic    │ Crate injects panic unwind  │ Relay catches unwind; returns DENY;     │
│                          │ during `is_authorized()`    │ stdio returns JSON-RPC error -32001.    │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 2. Keyring Read Timeout  │ Mock Keyring hangs for 30s  │ Lease acquisition aborts after 2s;      │
│                          │                             │ returns CredentialAcquisitionFailed.    │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 3. Target API 500 Error  │ WireMock returns HTTP 500   │ Relay records SUCCEEDED dispatch with   │
│                          │ Internal Server Error       │ exit_code=500; returns result to agent. │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 4. Network Disconnect    │ TCP socket severed mid-call │ Relay catches `std::io::ErrorKind`;     │
│                          │                             │ emits receipt with status NETWORK_ERROR.│
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 5. SQLite Lock Contention│ External process holds lock │ Ledger background queue retries with    │
│                          │ on `ledger.db`              │ exponential backoff (up to 5s) or fails.│
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 6. Disk Full (ENOSPC)    │ SQLite write fails with     │ Relay aborts tool execution; stdio pipe │
│                          │ `SQLITE_FULL`               │ returns fatal error; fails closed.      │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 7. Process `SIGKILL`     │ `kill -9 <relay_pid>` while │ SQLite WAL ensures ledger is clean on   │
│                          │ tool is in-flight           │ restart; in-flight action not recorded. │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 8. Corrupted Signing Key │ Disk private key overwritten│ Relay refuses to start; exits with      │
│                          │ with random bytes           │ exit code 1 and logs explicit key error.│
└──────────────────────────┴─────────────────────────────┴─────────────────────────────────────────┘
```

---

## 8. Fuzzing Strategy & Corpus Management

Continuous fuzz testing using `cargo-fuzz` (libFuzzer) targets all untrusted input parsers and deserializers:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       FUZZING TARGET SUITE                                       │
├──────────────────────────┬─────────────────────────────────────────┬─────────────────────────────┤
│ Fuzz Target Name         │ Target Function Under Test              │ Corpus Seed Sources         │
├──────────────────────────┼─────────────────────────────────────────┼─────────────────────────────┤
│ `fuzz_json_rpc_framing`  │ `mcp::framing::decode_stdio_stream`     │ RFC 8259 compliance suite   │
├──────────────────────────┼─────────────────────────────────────────┼─────────────────────────────┤
│ `fuzz_jcs_canonicalizer` │ `canonicalizer::rfc8785::canonicalize`  │ W3C JCS official test vectors│
├──────────────────────────┼─────────────────────────────────────────┼─────────────────────────────┤
│ `fuzz_sql_normalizer`    │ `normalizer::sql::parse_and_canonicalize`│ SQLGlot / SQLite test suite │
├──────────────────────────┼─────────────────────────────────────────┼─────────────────────────────┤
│ `fuzz_path_normalizer`   │ `normalizer::path::canonicalize_path`   │ Linux/POSIX path edge cases │
├──────────────────────────┼─────────────────────────────────────────┼─────────────────────────────┤
│ `fuzz_dsse_envelope`     │ `crypto::dsse::verify_and_decode`       │ in-toto attestation corpus  │
├──────────────────────────┼─────────────────────────────────────────┼─────────────────────────────┤
│ `fuzz_ledger_recovery`   │ `ledger::wal::recover_and_verify`       │ Corrupted SQLite DB samples │
└──────────────────────────┴─────────────────────────────────────────┴─────────────────────────────┘
```

### Fuzzing Invariant Assertions
Every fuzz harness asserts:
1. **No Panics:** Malformed inputs must return `Err(...)`, never trigger unhandled `panic!`.
2. **No Memory Leaks:** AddressSanitizer (`ASan`) and LeakSanitizer (`LSan`) run continuously during fuzz runs.
3. **Bounded CPU & Memory:** Input frames $> 4\text{ MB}$ or regex evaluations $> 10\text{ms}$ are aborted.

---

## 9. Regression Philosophy & Vulnerability Lifecycle

To guarantee that past vulnerabilities cannot recur, Relay mandates a strict **Triple-Lock Regression Protocol**:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                TRIPLE-LOCK REGRESSION PROTOCOL                                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

     Security Vulnerability Discovered / Reported
                         │
                         ▼
     ┌────────────────────────────────────────────────────────────────────────┐
     │ 1. ADVERSARIAL EXPLOIT TEST (`tests/security/cve_*.rs`)                │
     │    • Standalone reproduction script replicating exact attack vector.   │
     │    • MUST FAIL on unpatched codebase.                                  │
     └──────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
     ┌────────────────────────────────────────────────────────────────────────┐
     │ 2. CANONICAL REGRESSION UNIT/PROP TEST (`tests/regression/`)           │
     │    • Parameterized test added to standard CI suite.                    │
     │    • Integrated into daily `cargo test` runs.                          │
     └──────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
     ┌────────────────────────────────────────────────────────────────────────┐
     │ 3. DOCUMENTED SECURITY INVARIANT (`docs/architecture/A004`)            │
     │    • Explicit numbered invariant added to architecture specification.  │
     │    • Future refactors must preserve invariant.                         │
     └────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Release Quality & Security Gates

Relay enforces **four non-negotiable verification gates** before any build is certified:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   RELAY RELEASE QUALITY GATES                                    │
├────────────────────────┬────────────────────────────────────────────┬────────────────────────────┤
│ Quality Gate           │ Required Checks & Assertions               │ Enforcement Boundary       │
├────────────────────────┼────────────────────────────────────────────┼────────────────────────────┤
│ **1. Developer Gate**  │ • `cargo test --lib --bins` (All pass)     │ Pre-commit Git Hook        │
│                        │ • `cargo clippy --all-targets -- -D warnings`│ (`.git/hooks/pre-commit`)  │
│                        │ • `cargo fmt --check`                      │                            │
├────────────────────────┼────────────────────────────────────────────┼────────────────────────────┤
│ **2. CI Gate**         │ • Full test suite on Linux (x86_64, aarch64)│ GitHub Actions PR Gate     │
│                        │ • Full test suite on macOS (Apple Silicon) │ (Blocks Merge)             │
│                        │ • 26-Vector Adversarial Matrix: 100% Pass  │                            │
│                        │ • `proptest` 10,000 iterations / property  │                            │
├────────────────────────┼────────────────────────────────────────────┼────────────────────────────┤
│ **3. Security Gate**   │ • `cargo audit` (Zero vulnerabilities)     │ Nightly Security Pipeline  │
│                        │ • `cargo fuzz` (30 minutes / target)       │ (Blocks Release Candidate) │
│                        │ • LeakSanitizer + AddressSanitizer Clean   │                            │
│                        │ • Zero Secret Leakage Verification Pass    │                            │
├────────────────────────┼────────────────────────────────────────────┼────────────────────────────┤
│ **4. Release Gate**    │ • Golden Path E2E verification on real OS  │ Release Tag Creation       │
│                        │ • Static binary signature verification     │ (`cargo release`)          │
│                        │ • Binary reproducibility verification      │                            │
└────────────────────────┴────────────────────────────────────────────┴────────────────────────────┘
```

---

## 11. Test Observability & Secret Scrubbing

To prevent test suites from accidentally persisting real secrets or polluting developer logs:

### 1. Deterministic Mock Credentials
- Tests **never** utilize real external tokens or live Keyrings.
- The test harness uses standardized, deterministic synthetic test tokens with fixed entropy:
  - GitHub Token: `ghp_TESTING_MOCK_TOKEN_99999999999999999999`
  - Slack Token: `xoxb-TESTING-MOCK-SLACK-TOKEN-000000000000`
  - AWS Secret: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

### 2. Ephemeral Storage Isolation
- Every integration and E2E test instantiates an isolated temporary directory via `tempfile::TempDir`.
- SQLite database files (`ledger.db`), socket files, and test filesystems are automatically wiped upon test completion.

### 3. Redacted Test Tracing Subscriber
- The test harness installs a custom `tracing-subscriber` layer that asserts all logs contain zero raw tokens. If a test emits a string matching a secret pattern, the test **fails immediately with a log pollution assertion**.

---

## 12. Synthesis & Summary Tables

### 12.1 The Test Pyramid Summary

```
                      ┌───────────────────────────┐
                      │   14. FUZZING (LibFuzzer) │
                      ├───────────────────────────┤
                      │  13. ADVERSARIAL GAUNTLET │
                      ├───────────────────────────┤
                      │  12. END-TO-END (E2E)     │
                      ├───────────────────────────┤
                      │ 11. LEDGER INTEGRITY      │
                      ├───────────────────────────┤
                      │ 10. CRYPTOGRAPHIC PROOFS  │
                      ├───────────────────────────┤
                      │ 9. CREDENTIAL ISOLATION   │
                      ├───────────────────────────┤
                      │ 8. SUBPROCESS & PROXY     │
                      ├───────────────────────────┤
                      │ 7. PROTOCOL INTEGRATION   │
                      ├───────────────────────────┤
                      │ 6. CONNECTOR DRIVERS      │
                      ├───────────────────────────┤
                      │ 5. CEDAR POLICY ENGINE    │
                      ├───────────────────────────┤
                      │ 4. CANONICALIZATION (JCS) │
                      ├───────────────────────────┤
                      │ 3. PARSER SAFETY          │
                      ├───────────────────────────┤
                      │ 2. PROPERTY TESTS         │
                      ├───────────────────────────┤
                      │ 1. UNIT TESTS             │
                      └───────────────────────────┘
```

### 12.2 Definition of MVP Correctness

A build of Relay MVP is **Correct and Ready for Deployment** if and only if:

1. **Golden Path Invariant:** The canonical end-to-end execution flow succeeds with valid in-toto DSSE receipts and zero errors.
2. **Zero Ambient Credential Invariant:** Memory and child process inspection proves credentials exist solely in zeroized buffers during active dispatch.
3. **Adversarial Invariant:** All 26 attacks in the Adversarial Security Test Matrix are stopped deterministically with zero unauthorized state mutations.
4. **Canonical Invariant:** Identical semantic inputs produce identical `ActionHash` digests across Unicode, whitespace, and formatting variants.
5. **Ledger Integrity Invariant:** The SQLite ledger maintains an unbroken, monotonically increasing SHA-256 hash chain that detects single-bit tampering.
6. **Fail-Closed Invariant:** All simulated network partitions, timeouts, memory exhaustions, and engine panics fail closed with zero permissive leaks.
7. **Gate Invariant:** The test suite passes 100% of Developer, CI, Security, and Release quality gates on both Linux and macOS.
