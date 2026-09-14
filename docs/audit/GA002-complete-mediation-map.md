# Complete Mediation Map: Milestone GA002

**Document ID:** `AUD-MED-GA002`  
**Milestone:** `GA002 — Independent Security & Release Audit`  
**Auditor:** Principal External Security Reviewer  
**Date:** 2026-09-14  
**Status:** Complete Mediation Audit Map  

---

## 1. Executive Summary

This document independently traces every supported execution path in Relay v0.1.0 to verify that complete mediation is maintained across all operations without bypass paths, un-governed fallbacks, or cached authorization decisions.

---

## 2. Comprehensive Execution Path Tracing

### 2.1. Native Filesystem Connector Path
```text
[1] Entry Point:
    Agent sends JSON-RPC frame {"method": "tools/call", "params": {"name": "relay.fs.read_file", "arguments": {"path": "/workspace/data.txt"}}}
      ↓
[2] Gateway Framing & Strict Validation:
    `relay_mcp::gateway::handle_agent_frame` validates JSON structure, bounds frame size (MAX: 1MB), rejects duplicate keys.
      ↓
[3] Canonicalization:
    `relay_canonical::ActionCanonicalizer::canonicalize` normalizes path (resolving '.', '..', symlinks), sorts JSON keys (RFC 8785),
    computes canonical `ActionHash`.
      ↓
[4] Authorization (Cedar PEP):
    `relay_policy::engine::DefaultPolicyEngine::evaluate` checks principal against `Relay::Filesystem` resource with `fs.read_file` action.
      ↓
[5] Operator Approval:
    If policy returns `ApprovalRequired`, prompts Operator on `/dev/tty` (or fails closed if headless).
      ↓
[6] Credential Acquisition:
    Filesystem connector operates locally without network credential lease.
      ↓
[7] Governed Execution:
    `relay_connectors::fs::FilesystemConnector::execute_governed_with_receipt` enforces read size limits (10MB) and executes file read.
      ↓
[8] Cryptographic Evidence:
    `relay_receipts::signer::Ed25519ReceiptSigner::sign_receipt` scrubs output for secrets, binds `ActionHash` + `PolicyDigest`, signs DSSE envelope.
      ↓
[9] Ledger Persistence:
    `relay_ledger::sqlite::SqliteLedger::append` records entry into append-only hash chain.
```

### 2.2. Native PostgreSQL Connector Path
```text
[1] Entry Point:
    Agent sends JSON-RPC frame {"method": "tools/call", "params": {"name": "relay.postgres.query", "arguments": {"query": "SELECT * FROM users"}}}
      ↓
[2] Gateway Framing & Strict Validation:
    `relay_mcp::gateway::handle_agent_frame` strict parsing.
      ↓
[3] Canonicalization:
    `ActionCanonicalizer` parses SQL AST with `sqlparser`, validates read-only statements, sorts JSON arguments, generates `ActionHash`.
      ↓
[4] Authorization (Cedar PEP):
    `DefaultPolicyEngine` evaluates request against `Relay::Postgres` entity for table / database resources.
      ↓
[5] Operator Approval:
    Step-up approval on `/dev/tty` if mutation/DDL is requested.
      ↓
[6] Credential Acquisition:
    `relay_credentials::broker::JitCredentialBroker` issues ephemeral single-use `CredentialLease` for database password from OS keyring.
      ↓
[7] Governed Execution:
    `relay_connectors::postgres::PostgresConnector::execute_governed_with_receipt` connects via TLS 1.3 (`rustls`), executes query, zeroizes password on drop.
      ↓
[8] Cryptographic Evidence:
    `Ed25519ReceiptSigner` scrubs response and signs DSSE receipt.
      ↓
[9] Ledger Persistence:
    `SqliteLedger` commits Merkle hash-chain entry.
```

### 2.3. Native GitHub Connector Path
```text
[1] Entry Point:
    Agent sends JSON-RPC frame {"method": "tools/call", "params": {"name": "relay.github.create_issue", "arguments": {...}}}
      ↓
[2] Gateway & Canonicalization:
    Strict frame validation, repository URI canonicalization (`github://owner/repo`), `ActionHash` computation.
      ↓
[3] Authorization (Cedar PEP):
    `DefaultPolicyEngine` evaluates `Relay::GitHub` resource and action permissions.
      ↓
[4] Operator Approval:
    Required for write/delete operations; prompted on `/dev/tty`.
      ↓
[5] Credential Acquisition:
    `JitCredentialBroker` retrieves vaulted GitHub PAT.
      ↓
[6] Governed Execution:
    `relay_connectors::github::GitHubConnector::execute_governed_with_receipt` executes REST request against `api.github.com` via HTTPS.
      ↓
[7] Evidence & Ledger:
    Secret scrubber verifies no PAT appears in response or receipt; Ed25519 DSSE envelope signed and committed to SQLite ledger.
```

### 2.4. External MCP Subprocess & Loopback Proxy Egress Path
```text
[1] Entry Point:
    Agent calls an external MCP tool provided by a third-party subprocess.
      ↓
[2] Gateway & Canonicalization:
    `ActionCanonicalizer` generates `ActionHash` for the external tool call.
      ↓
[3] Cedar Authorization & Session Issuance:
    `ProxySessionManager::create_lease` generates ephemeral 256-bit `RELAY_PROXY_AUTH` token ($T_{\text{lease}}$, 30s TTL, bound to `ActionHash`).
      ↓
[4] Subprocess Sandbox Spawn:
    `EgressSandboxLauncher::spawn`:
    - Linux: `pre_exec` unshares `CLONE_NEWUSER | CLONE_NEWNET` (blocks raw sockets, loopback only).
    - macOS/Windows: Injects sanitized `HTTP_PROXY`, `HTTPS_PROXY`, `RELAY_PROXY_AUTH`.
      ↓
[5] Outbound Egress Interception:
    Subprocess dials loopback proxy on `127.0.0.1:<ephemeral>`.
    Proxy validates `RELAY_PROXY_AUTH`, checks pre-DNS blacklist (`169.254.169.254`, `metadata.google.internal`),
    pins resolved IP, and evaluates Cedar destination policy on `Relay::NetworkEndpoint`.
      ↓
[6] Vaulted JIT Credential Injection:
    `CredentialInjector` matches upstream host and injects vaulted header (e.g. `Authorization: Bearer <secret>`) into the TCP stream.
      ↓
[7] Upstream Dispatch & Splice:
    Bidirectional copy between client and upstream server.
      ↓
[8] Tool Completion & Session Burning:
    Tool call returns -> `ProxySessionManager::burn_lease` burns token; post-action reuse is blocked.
      ↓
[9] Evidence & Ledger:
    Action Receipt signed with DSSE envelope and committed to SQLite ledger.
```

---

## 3. Review for Alternate Entry Points & Fallbacks

| Evaluated Surface | Audit Finding | Verdict |
|:---|:---|:---:|
| **Test Hooks in Release Binary** | No test hooks or backdoor bypasses exist in release builds (`cfg(test)` isolated). | `PASS` |
| **Direct Connector Calls** | Direct connector methods require matching `&PolicyDecision` and signer. | `PASS` |
| **Un-sandboxed Fallback** | Linux sandbox failure in `pre_exec` aborts spawn (`SI-024` fail-closed); never falls back. | `PASS` |
| **Cached Policy Decisions** | No global policy decision cache; Cedar evaluates every action by `ActionHash`. | `PASS` |
| **Async Task Replay** | Post-action async attempts fail closed upon lease burning (`SI-020`). | `PASS` |

---

## 4. Mediation Verification Verdict

$$\text{Complete Mediation Audit: } \mathbf{PASSED\ (NO\ BYPASS\ VULNERABILITIES\ IDENTIFIED)}$$
