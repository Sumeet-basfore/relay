# A004: Relay MVP Security Invariants & Security Contract

**Document ID:** `A004-security-invariants`  
**Date:** September 2026  
**Status:** Approved Security Contract / Implementation Baseline  
**Target System:** Relay MVP (Local-First Zero-Trust MCP Security Gateway & Credential Broker)  
**Author:** Principal Security Architect  
**Corpus Dependencies:** `A001-system-architecture`, `A002-domain-model`, `R015-build-gate`, `R009` (Trust Boundaries), `R010` (JIT Credentials), `R011` (Action Receipts), `R012` (MCP Boundary)

---

## Executive Summary

This document establishes the **formal security contract** for the Relay MVP implementation. It translates the architectural principles of `A001` and domain boundaries of `A002` into explicit, testable, and non-negotiable **Security Invariants (SIs)**.

This document serves as the implementation gate for Relay. Every invariant specified herein must be enforced at a designated enforcement point (compile-time, runtime, OS-level, or procedural) and validated by automated tests before the system is certified for deployment.

### Non-Negotiable Engineering Rules
1. **Do NOT add product features** to satisfy security invariants; solve them at the boundary.
2. **Do NOT weaken guarantees** to simplify implementation.
3. **Do NOT claim guarantees stronger** than what the local operating system and protocol boundaries permit.

---

## 1. Security Objectives

The Relay MVP is engineered to satisfy ten primary security objectives:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     MVP SECURITY OBJECTIVES                                      │
├────────────────────────────────┬────────────────────────────────┬────────────────────────────────┤
│ 1. Zero Ambient Agent Secrets  │ 2. Deterministic Authorization │ 3. Execution Binding           │
│ The agent process possesses    │ Authorization is a pure        │ The executed payload is        │
│ zero target API keys or tokens │ boolean function over canonical│ byte-for-byte identical to the  │
│ in env, disk, or memory.       │ typed inputs.                  │ authorized payload.            │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 4. Default Deny Architecture   │ 5. Approval Integrity          │ 6. Single-Action Lease Scope   │
│ Any unmapped tool, ambiguous   │ Interactive human approvals are│ JIT credentials exist only for │
│ parameter, or error is DENIED. │ bound to the exact ActionHash  │ a single authorized action and │
│                                │ displayed on the direct TTY.   │ are zeroized immediately.      │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 7. Evidence Non-Repudiation    │ 8. Ledger Hash-Chain Integrity │ 9. Process Isolation Boundary  │
│ Action receipts are signed by  │ Receipts are stored in an      │ Host OS kernel memory & IPC    │
│ an isolated Ed25519 key.       │ append-only SHA-256 ledger.    │ protections are strictly upheld│
├────────────────────────────────┼────────────────────────────────┴────────────────────────────────┤
│ 10. Universal Fail-Closed      │ Any parser error, timeout, serialization mismatch, or internal │
│ Behavior                       │ panic results in immediate execution abortion.                 │
└────────────────────────────────┴────────────────────────────────────────────────────────────────┘
```

1. **No Ambient Agent Credentials:** Agent runtimes (Claude, Cursor, LangGraph, custom loops) operate with zero access to target API credentials (e.g., GitHub PATs, AWS IAM tokens, PostgreSQL connection strings). Target credentials reside exclusively in Relay's credential store or OS keyring.
2. **Deterministic Authorization:** Policy decisions depend strictly on canonicalized, typed inputs and explicit Cedar policies. Evaluator state is hermetic; no ambient, unmodelled variables influence decisions.
3. **Execution Binding:** The exact payload evaluated by Cedar is the exact payload dispatched for execution. No re-parsing, intermediate mutation, or ambient parameter injection occurs between authorization and execution.
4. **Default Deny:** If an action, tool, parameter, or actor is not explicitly permitted by a Cedar policy, authorization evaluates to `DENY`.
5. **Approval Integrity:** When human approval is required, the prompt displayed on `/dev/tty` shows the canonical payload. Approval is bound cryptographically to `ActionHash`. An approval cannot be reused, transferred, or applied to mutated parameters.
6. **Credential Scope:** Leased credentials are injected just-in-time (JIT) into transient, zeroized memory buffers for a single execution dispatch, or injected into a loopback egress proxy stream.
7. **Evidence Integrity:** Action receipts are structured in-toto v1.0 statements wrapped in DSSE (RFC 9598) envelopes signed by an Ed25519 key managed exclusively by Relay.
8. **Ledger Integrity:** Receipts are appended to a local SQLite database where each entry is cryptographically linked to the previous entry via SHA-256 hash chaining.
9. **Process Isolation Assumptions:** Relay relies on OS kernel process isolation, private virtual memory spaces, `/proc` permission masks (`PR_SET_DUMPABLE=0`), and restricted filesystem permissions (`0600`/`0700`).
10. **Fail-Closed Behavior:** Any unexpected condition, schema mismatch, AST parsing failure, Cedar evaluation timeout, secret retrieval error, or network anomaly triggers an immediate termination with an error returned to the agent.

---

## 2. Formal Security Invariants

Each invariant is specified with an unambiguous ID, formal statement, architectural rationale, enforcement point, failure behavior, verification test, and enforcement mechanism classification.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECURITY INVARIANTS MATRIX                                     │
├─────────┬──────────────────────────────────────────────────────┬─────────────────────────────────┤
│ ID      │ Short Summary                                        │ Primary Enforcement Point       │
├─────────┼──────────────────────────────────────────────────────┼─────────────────────────────────┤
│ SI-001  │ Agent receives no target credentials                 │ Ingress Transport / Env Sanitizer│
│ SI-002  │ Authorization precedes execution                     │ Dispatcher State Machine        │
│ SI-003  │ Denied actions are never dispatched                  │ Dispatcher Gate                 │
│ SI-004  │ Approval is bound to ActionHash                      │ TTY Approval Interceptor        │
│ SI-005  │ Authorized representation equals executed rep.       │ In-Memory Invariant (Zero Copy) │
│ SI-006  │ CredentialLease is scoped to one authorized action   │ Credential Broker & Nonce Burner│
│ SI-007  │ Secrets do not enter persistent storage              │ Domain Memory Manager           │
│ SI-008  │ Secrets do not enter logs, traces, or receipts       │ Redaction Filter & Type System  │
│ SI-009  │ Receipt evidence cannot be silently modified         │ Ed25519 DSSE + Hash-Chain Ledger│
│ SI-010  │ Policy version is bound to authorization decision    │ Cedar Engine Wrapper            │
│ SI-011  │ Tool identity is unambiguous                         │ Namespace Resolver              │
│ SI-012  │ Resource identity is canonical                       │ Path/URI Normalizer             │
│ SI-013  │ Canonicalization divergence cannot alter semantics   │ AST Domain Normalizer           │
│ SI-014  │ Security-sensitive failures fail closed              │ Error Handler                   │
│ SI-015  │ Relay does not claim external mutation without proof │ Receipt Engine Epistemology     │
│ SI-016  │ Nonce uniqueness prevents action replay              │ SQLite Monotonic State Tracker  │
│ SI-017  │ Transient memory buffers are zeroized on drop        │ `ZeroizeOnDrop` Rust Types      │
│ SI-018  │ MCP Subprocesses receive zero ambient network creds  │ Process Spawn & Egress Proxy    │
└─────────┴──────────────────────────────────────────────────────┴─────────────────────────────────┘
```

---

### SI-001: Agent Receives No Target Credentials

* **Statement:** The agent client process, context window, and stdio streams must never receive, observe, or store target service credentials (API keys, passwords, bearer tokens, private keys).
* **Rationale:** Completely eliminates credential exfiltration via prompt injection, model jailbreaks, context dumps, or rogue agent sub-processes.
* **Enforcement Point:** Relay MCP Ingress / Stdio Transport Layer and Egress Sanitizer.
* **Failure Behavior:** If a target secret is detected in outbound MCP responses, Relay intercepts the payload, redacts the stream, logs a fatal security alert, and returns a sanitized generic error.
* **How It Is Tested:** 
  1. Inspect environment variables and memory space of the agent process during active tool calls to verify zero target tokens exist.
  2. Attempt prompt-injection attacks requesting raw tool configurations; assert response contains only tool schema, never credential fields.
* **Enforcement Mechanism:** Architectural / Runtime.

---

### SI-002: Authorization Precedes Execution

* **Statement:** No native connector or MCP subprocess execution dispatch may begin until an `AuthorizationRequest` has been evaluated by Cedar and resulted in an explicit `PolicyDecision::Allow` (or `ApprovalState::Approved`).
* **Rationale:** Prevents race conditions, speculative execution, or out-of-order execution bugs from triggering unintended state mutations.
* **Enforcement Point:** `ExecutionDispatcher::dispatch` state machine.
* **Failure Behavior:** Attempting to invoke execution without a valid, matching `Decision::Allow` token causes a compile-time or runtime type failure (`UnauthorizedActionDispatchAttempt`).
* **How It Is Tested:** Integration test attempting to bypass the Cedar PDP by invoking `ConnectorExecutor::execute` with an unapproved or pending `Action` aggregate. Assert execution is rejected with error.
* **Enforcement Mechanism:** Compile-time (Rust Type System Typestate Pattern) & Runtime.

---

### SI-003: Denied Actions Are Never Dispatched

* **Statement:** If the Cedar policy engine evaluates to `PolicyDecision::Deny`, or if a human operator denies approval, the target connector or subprocess must not be invoked under any condition.
* **Rationale:** Guarantees absolute policy enforcement authority.
* **Enforcement Point:** Dispatcher Gate.
* **Failure Behavior:** Action state transitions immediately to `ActionState::Settled(SettlementReason::Denied)`. A JSON-RPC error response (`code: -32003`) is returned to the agent.
* **How It Is Tested:** Configure Cedar policy `forbid(principal, action, resource)`. Issue matching tool call. Assert zero I/O occurs on target API/subprocess mock and JSON-RPC error is returned.
* **Enforcement Mechanism:** Runtime.

---

### SI-004: Approval Is Bound to ActionHash

* **Statement:** An interactive human approval is valid exclusively for the exact `ActionHash` (SHA-256 of canonical action request) presented on the `/dev/tty` interface.
* **Rationale:** Prevents Time-of-Check to Time-of-Use (TOCTOU) parameter swapping attacks where an agent requests approval for a benign action but executes a malicious one.
* **Enforcement Point:** `TtyApprovalManager` & `Action::transition_to_approved`.
* **Failure Behavior:** If the `ActionHash` inside the returned `Approval` entity does not match the active `Action.action_hash`, the approval is rejected and the action transitions to `Failed`.
* **How It Is Tested:** Inject a human approval approving `ActionHash_A` into an execution workflow currently processing `ActionHash_B`. Assert execution fails with `ApprovalHashMismatch`.
* **Enforcement Mechanism:** Runtime.

---

### SI-005: Authorized Representation Equals Executed Representation

* **Statement:** The parsed and normalized in-memory data representation evaluated by Cedar must be the exact identical data structure passed to the execution connector.
* **Rationale:** Eliminates parser-differential attacks where the policy engine authorizes one JSON string representation, but a secondary parser decodes different values at execution time.
* **Enforcement Point:** In-Memory Execution Pipeline (`Arc<CanonicalActionPayload>`).
* **Failure Behavior:** No intermediate re-serialization or string round-tripping occurs. The connector receives the exact parsed Rust struct that was checked by Cedar.
* **How It Is Tested:** Fuzz test injecting irregular JSON (duplicate keys, unescaped unicode, whitespace variants). Verify that Cedar evaluation and native connector execution observe the exact same field values.
* **Enforcement Mechanism:** Compile-time (Memory Ownership / Zero-Copy In-Memory Passing).

---

### SI-006: CredentialLease Is Scoped to One Authorized Action

* **Statement:** Every JIT credential lease is minted for exactly one `ActionId`, bound to a single execution attempt, and invalidated immediately upon execution completion or timeout.
* **Rationale:** Prevents credential reuse, lease hoarding, or replay attacks.
* **Enforcement Point:** `CredentialBroker` & `NonceManager`.
* **Failure Behavior:** Attempting to retrieve a credential using an expired, already-burned, or non-matching `ActionId` returns `CredentialLeaseExhausted`.
* **How It Is Tested:** Request a credential for `Action_1`. Execute `Action_1`. Attempt to use the same lease token for `Action_2`. Assert rejection.
* **Enforcement Mechanism:** Runtime.

---

### SI-007: Secrets Do Not Enter Persistent Application Storage

* **Statement:** Raw secret strings (passwords, tokens, private keys) must never be written to SQLite databases, disk logs, configuration files, or temporary filesystem storage.
* **Rationale:** Ensures that compromising the local filesystem or stealing `.relay/ledger.db` yields zero plaintext credentials.
* **Enforcement Point:** SQLite Ledger Writer & Serialization Traits.
* **Failure Behavior:** The SQLite schema enforces storage of `KeyAlias` strings and `SecretFingerprint` hashes only. Any attempt to pass raw secret bytes fails schema type constraints.
* **How It Is Tested:** Perform 1,000 tool executions with mock secrets. Run automated binary grep and regex scanners across `.relay/ledger.db`, `.relay/config.toml`, and `/tmp`. Assert zero secret occurrences.
* **Enforcement Mechanism:** Compile-time (Opaque Types) & Runtime (Automated Store Scans).

---

### SI-008: Secrets Do Not Enter Logs, Traces, or Receipts

* **Statement:** Secret material must never appear in `tracing::event!`, `println!`, OpenTelemetry spans, stderr outputs, or signed `ActionReceipt` payloads.
* **Rationale:** Prevents accidental secret leakage to observability pipelines, centralized SIEMs, or terminal scrollback buffers.
* **Enforcement Point:** Type System (`secrecy::SecretString`), Custom `Debug` / `Display` Implementations, and Tracing Subscriber Layers.
* **Failure Behavior:** `Debug` formatting on secret-bearing types prints `[REDACTED]`. The tracing subscriber strips header fields matching `Authorization`, `Cookie`, or known token patterns.
* **How It Is Tested:** Unit test triggering errors on all secret-handling paths while capturing tracing logs. Assert logs contain `[REDACTED]` and zero matching secret substrings.
* **Enforcement Mechanism:** Compile-time (`secrecy` crate) & Runtime.

---

### SI-009: Receipt Evidence Cannot Be Silently Modified

* **Statement:** Any modification, truncation, or deletion of past receipts in `.relay/ledger.db` must be detected upon the next verification or append operation.
* **Rationale:** Ensures non-repudiation and provides mathematical tamper-evidence for post-incident forensics.
* **Enforcement Point:** SQLite Hash-Chain Verifier & Ed25519 DSSE Signature Validator.
* **Failure Behavior:** When `relay verify` or `Ledger::append` detects a broken hash chain ($H_n \ne \text{SHA256}(H_{n-1} \mathbin{\Vert} \text{Payload}_n)$), the ledger enters a read-only locked state and emits a critical tampering alert.
* **How It Is Tested:** Execute 5 actions. Manually edit row 3 in `ledger.db` using a direct SQLite CLI command. Run `relay verify`. Assert detection with exit code `1` and exact row identification.
* **Enforcement Mechanism:** Runtime (Cryptographic Verification).

---

### SI-010: Policy Version Is Bound to the Authorization Decision

* **Statement:** Every `PolicyDecision` and signed `ActionReceipt` must record the exact cryptographic hash (`PolicySetHash`) of the active Cedar policy file evaluated during authorization.
* **Rationale:** Prevents retrospective policy tampering where an attacker modifies policies on disk and claims an old action was authorized under the new rules.
* **Enforcement Point:** `CedarEngine::evaluate`.
* **Failure Behavior:** The policy hash is computed at engine initialization and immutably stamped into every `PolicyDecision`. If the on-disk policy file is modified during runtime without reloading, the hash mismatch is flagged.
* **How It Is Tested:** Verify that changing a policy on disk changes the `policy_set_hash` recorded in the next generated `ActionReceipt`.
* **Enforcement Mechanism:** Runtime.

---

### SI-011: Tool Identity Is Unambiguous

* **Statement:** Every tool capability registered in Relay must possess a globally unique, namespaced identifier (`server_id.tool_name`) and an immutable SHA-256 schema digest computed at registration.
* **Rationale:** Prevents tool shadowing, registration collisions, and malicious schema mutation by untrusted MCP servers.
* **Enforcement Point:** `ToolRegistry::register` & `tools/list` normalizer.
* **Failure Behavior:** Any attempt by an MCP server to register a tool without a valid namespace, or to dynamically mutate a tool's schema without re-registration, triggers registration rejection.
* **How It Is Tested:** Attempt to register two tools with the name `read_file` from different servers without namespaces. Assert namespace prefixing is enforced.
* **Enforcement Mechanism:** Runtime.

---

### SI-012: Resource Identity Is Canonical

* **Statement:** All resource identifiers (file paths, URIs, database entities) must be resolved to their canonical representation before evaluation by Cedar.
* **Rationale:** Defeats path traversal attacks (`/workspace/../etc/passwd`), relative path ambiguities, and symlink escapes.
* **Enforcement Point:** `ResourceUri::canonicalize` / Path Resolver.
* **Failure Behavior:** If a resource path contains invalid traversals or cannot be resolved within permitted root directories (`roots/list`), the normalizer rejects the request before policy evaluation.
* **How It Is Tested:** Submit tool call with `path: "/workspace/src/../../etc/shadow"`. Assert resource normalizer outputs `file:///etc/shadow` and Cedar evaluates the canonical path, blocking the write.
* **Enforcement Mechanism:** Runtime.

---

### SI-013: Canonicalization Divergence Cannot Alter Authorization Semantics

* **Statement:** When tool parameters contain structured domain sub-languages (SQL queries, shell commands, JSON strings), authorization must evaluate parsed AST entities rather than unnormalized raw strings.
* **Rationale:** Prevents semantic evasion attacks where SQL comments, whitespace variations, or quote escapes deceive string-based regex policies.
* **Enforcement Point:** Domain-Specific AST Parsers (`sqlparser-rs`, Shell AST Normalizer).
* **Failure Behavior:** If a structured payload cannot be cleanly parsed into a recognized AST, authorization fails closed with `InvalidPayloadStructure`.
* **How It Is Tested:** Issue a SQL query with comment injection: `SELECT/**/password/**/FROM/**/users`. Assert AST normalizer extracts target table `users` and target columns `password`, triggering the forbid rule.
* **Enforcement Mechanism:** Runtime.

---

### SI-014: Security-Sensitive Failures Fail Closed

* **Statement:** Any unexpected error, unhandled exception, network timeout, keyring lock, or internal panic during policy evaluation, credential acquisition, or execution dispatch must immediately terminate the action with `DENY` or `FAILED`.
* **Rationale:** Guarantees that system degradation or fault injection attacks never result in accidental open access.
* **Enforcement Point:** Global Error Handling Boundary & Panic Hooks (`std::panic::catch_unwind`).
* **Failure Behavior:** The active transaction is aborted, rented resources are freed, memory is zeroized, and an error frame is returned over JSON-RPC.
* **How It Is Tested:** Inject faults into Cedar PDP (mock memory exhaustion, synthetic panic). Assert action fails closed and zero downstream traffic is emitted.
* **Enforcement Mechanism:** Runtime & OS-level.

---

### SI-015: Relay Does Not Claim External Physical Mutation Without Evidence

* **Statement:** An `ActionReceipt` must explicitly distinguish between Relay-asserted facts (authorization decision, payload hash), Relay-observed facts (HTTP status code, stdout byte count), and unverified external facts (upstream database state).
* **Rationale:** Prevents misleading audit guarantees; Relay proves *what was dispatched and received*, not unobservable downstream third-party side effects.
* **Enforcement Point:** `ActionReceipt` schema & DSSE Predicate Builder.
* **Failure Behavior:** Receipt predicates enforce distinct schema fields for `relay_assertions` vs `observed_execution` vs `target_claims`.
* **How It Is Tested:** Inspect schema of generated `ActionReceipt`. Verify that HTTP response body is categorized under `observed_result` and not asserted as a verified database transaction.
* **Enforcement Mechanism:** Compile-time (Domain Schema Types).

---

### SI-016: Nonce Uniqueness Prevents Action Replay

* **Statement:** Every action proposal must carry a unique, monotonically increasing nonce/UUIDv7. An action token can be executed exactly once.
* **Rationale:** Prevents replay attacks where an attacker re-sends a previously authorized JSON-RPC frame.
* **Enforcement Point:** `NonceManager` & SQLite State Store.
* **Failure Behavior:** Resubmitting an identical `proposal_id` or reused `ActionHash` is rejected with `DuplicateActionNonce`.
* **How It Is Tested:** Replay an identical, valid `tools/call` JSON-RPC frame twice. Assert first call succeeds and second call fails immediately.
* **Enforcement Mechanism:** Runtime.

---

### SI-017: Transient Memory Buffers Are Zeroized on Drop

* **Statement:** All in-memory allocations containing raw secrets, decrypted keys, or sensitive credential tokens must implement automatic memory zeroization upon deallocation.
* **Rationale:** Prevents secret leakage via heap fragmentation, memory dumps, or use-after-free inspection.
* **Enforcement Point:** Rust RAII Drop Implementation (`zeroize::ZeroizeOnDrop`).
* **Failure Behavior:** When a `SecretBuffer` leaves scope, volatile writes overwrite the underlying memory with zeros before deallocation.
* **How It Is Tested:** Allocate a secret in a `SecretBuffer`, drop it, and inspect the raw memory address. Assert memory contains exclusively zeroes.
* **Enforcement Mechanism:** Compile-time & Runtime.

---

### SI-018: MCP Subprocesses Receive Zero Ambient Network Credentials

* **Statement:** Third-party MCP subprocesses spawned by Relay must have their environment variables stripped of ambient host credentials and their outbound network traffic routed exclusively through the Relay loopback egress proxy.
* **Rationale:** Prevents third-party tool subprocesses from directly stealing host credentials or bypassing Relay policy enforcement by opening raw internet sockets.
* **Enforcement Point:** Subprocess Command Builder (`std::process::Command`) & Linux Network Namespaces.
* **Failure Behavior:** Subprocess environment is cleared (`env_clear()`); only explicit `HTTP_PROXY=http://127.0.0.1:<port>` is injected.
* **How It Is Tested:** Spawn a test MCP subprocess that attempts to print `std::env::vars()`. Assert all host AWS/GitHub/OAuth variables are absent.
* **Enforcement Mechanism:** Runtime & OS-level.

---

## 3. Trust Model

Relay classifies all entities in its operational universe into four strict trust tiers:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       RELAY TRUST MODEL                                          │
├───────────────────┬───────────────────┬──────────────────────┬───────────────────────────────────┤
│ TRUST CLASSIF.    │ COMPONENT         │ SOURCE OF ASSURANCE  │ FAILURE / COMPROMISE IMPACT       │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **UNTRUSTED**     │ Agent / LLM       │ None. Assumed        │ Emits malicious tool calls,       │
│                   │ Runtime           │ compromised by PI.   │ prompt injections, malformed args.│
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **UNTRUSTED**     │ External Web/Data │ None. Untrusted.     │ Contains indirect injections.     │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **PARTIALLY       │ 3rd-Party MCP     │ Process isolation &  │ May attempt to exfiltrate data or │
│ TRUSTED**         │ Subprocess        │ stripped environment.│ emit malformed output.            │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **PARTIALLY       │ Target API        │ TLS & Upstream Auth. │ May experience outage or return   │
│ TRUSTED**         │ (GitHub/Postgres) │                      │ unexpected errors.                │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ Relay Core Binary │ Memory-safe Rust &   │ If compromised, all policy and    │
│                   │                   │ deterministic logic. │ credential guarantees fail.       │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ Cedar PDP Engine  │ Formally verified    │ Evaluates deterministic boolean   │
│                   │                   │ SMT/Z3 semantics.    │ access decisions.                 │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ OS Keyring / KMS  │ Host OS Secure       │ Holds master secrets; protected   │
│                   │                   │ Enclave / SecretServ.│ by OS user account boundary.      │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ Native Connectors │ In-process Rust      │ Executes authorized calls with    │
│                   │                   │ implementations.     │ JIT-leased credentials.           │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ Egress Proxy      │ In-process loopback  │ Injects credentials into          │
│                   │                   │ Hyper proxy.         │ authorized HTTP request streams.  │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ Signing Key       │ Local Ed25519 key;   │ Generates cryptographic DSSE      │
│                   │                   │ restricted file perms│ signatures for Action Receipts.   │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **TRUSTED (TCB)** │ SQLite Ledger     │ Append-only WAL with │ Stores tamper-evident hash chain. │
│                   │                   │ SHA-256 hash chains. │ Tampering triggers hard lock.     │
├───────────────────┼───────────────────┼──────────────────────┼───────────────────────────────────┤
│ **EXTERNAL**      │ Upstream Identity │ OIDC/OAuth Provider. │ Token issuance and expiry.        │
│                   │ Provider (IdP)    │                      │                                   │
└───────────────────┴───────────────────┴──────────────────────┴───────────────────────────────────┘
```

---

## 4. Security Boundary Matrix

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       SECURITY BOUNDARY MATRIX                                         │
├──────────────────────────┬─────────────────────────────┬───────────────────────────┬───────────────────┤
│ BOUNDARY                 │ THREAT                      │ REQUIRED CONTROL          │ RESIDUAL RISK     │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Agent → Relay**        │ Prompt injection, malformed │ RFC 8785 JCS validation,  │ Denial of Service │
│ (Stdio Transport)        │ JSON, parameter mutation,   │ Cedar ABAC evaluation,    │ via high-frequency│
│                          │ tool shadowing.             │ AST normalizers, nonces.  │ tool invocations. │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Relay → Connector**    │ Parameter tampering, race   │ Zero-copy in-memory AST   │ Logical bug in    │
│ (In-Process Rust)        │ conditions, memory leaks.   │ passing, `SecretString`.  │ native connector. │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Relay → MCP Subprocess**│ Ambient token exfiltration, │ `env_clear()`, isolated   │ Subprocess local  │
│ (Local Subprocess)       │ rogue process execution.    │ pipe I/O, process groups. │ computation hang. │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Subprocess → Network** │ Direct unauthenticated or   │ Linux Network Namespaces  │ Unconfined host   │
│ (Outbound Egress)        │ out-of-band network calls.  │ (`netns`) or proxy forcing│ code execution.   │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Relay → Keyring**      │ Unauthorized local process  │ OS user account DAC,      │ Root user / kernel│
│ (Credential Retrieval)   │ credential access.          │ memory zeroization.       │ level compromise. │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Relay → SQLite**       │ Ledger record tampering,    │ SHA-256 hash chaining,    │ Direct file       │
│ (Persistence)            │ row deletion or truncation. │ strict `0600` permissions.│ deletion (detect) │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Relay → Signing Key**  │ Private key exfiltration    │ `PR_SET_DUMPABLE=0`,      │ Host memory dump  │
│ (Receipt Engine)         │ via memory dump or core.    │ zeroized buffers on drop. │ by root user.     │
├──────────────────────────┼─────────────────────────────┼───────────────────────────┼───────────────────┤
│ **Human → Approval TTY** │ Phishing, confusing diffs,  │ Direct `/dev/tty` prompt, │ Human operator    │
│ (Interactive HITL)       │ synthetic input injection.  │ canonical parameter diff. │ rubber-stamping.  │
└──────────────────────────┴─────────────────────────────┴───────────────────────────┴───────────────────┘
```

---

## 5. Secret Lifecycle Specification

Secrets in Relay follow a strict, deterministic lifecycle designed around the **Anti-Vault Principle**: secrets are transient memory-only execution primitives that never become persisted entities.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     SECRET LIFECYCLE PHASES                                      │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

   [ 1. ACQUIRE ] ──► [ 2. HOLD ] ──► [ 3. USE ] ──► [ 4. EXPIRE ] ──► [ 5. ZEROIZE ]
```

### Detailed Lifecycle Phases

1. **Acquire:** Secret is fetched on-demand from OS Keyring or decrypted from local store using master key. Returned strictly as an opaque `SecretBuffer`.
2. **Hold:** Held in volatile RAM allocated with `mprotect(PROT_READ | PROT_WRITE)`. Paging to swap is disabled via `mlock()`.
3. **Use:** Passed by reference exclusively to the HTTP client header builder or database connection initializer.
4. **Expire:** Lease timer fires (default: single-use, max 30s) or execution completes. Lease token is burned.
5. **Zeroize:** `SecretBuffer` is dropped. Memory is overwritten with zeroes (`volatile_set`) and memory lock is released.

### Accidental Leakage Surface Audit

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SECRET LEAKAGE VULNERABILITY AUDIT                               │
├──────────────────────────┬─────────────────────────────┬─────────────────────────────────────────┤
│ POTENTIAL LEAK LOCATION  │ RISK LEVEL WITHOUT CONTROL  │ RELAY ENFORCED MITIGATION               │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ Heap Memory              │ CRITICAL                    │ Wrapped in `SecretString`; `ZeroizeOnDrop`│
│ Stack Memory             │ HIGH                        │ Avoid pass-by-value copies; stack zero. │
│ Process Environment      │ CRITICAL                    │ `env_clear()` before spawning children. │
│ Command Line Arguments   │ CRITICAL                    │ Never pass tokens in CLI flags (`argv`).│
│ `/proc/<pid>/cmdline`    │ HIGH                        │ Clean process invocation arguments.     │
│ Subprocess Environment   │ CRITICAL                    │ Loopback proxy auth replaces env tokens.│
│ Application Logs         │ HIGH                        │ Tracing subscriber header redaction.    │
│ Panic Output / Backtrace │ HIGH                        │ Custom panic hook suppresses locals.    │
│ OS Core Dumps            │ HIGH                        │ `prctl(PR_SET_DUMPABLE, 0)` disabled.   │
│ SQLite Ledger            │ HIGH                        │ Schema stores only `SecretFingerprint`. │
│ Action Receipts          │ CRITICAL                    │ in-toto statements contain zero tokens. │
│ OpenTelemetry Tracing    │ MEDIUM                      │ GenAI spans scrubbed of auth headers.   │
│ Metrics Scrapes          │ LOW                         │ Metrics track counts and durations only.│
└──────────────────────────┴─────────────────────────────┴─────────────────────────────────────────┘
```

---

## 6. Time-of-Check to Time-of-Use (TOCTOU) Analysis

The lifecycle from action proposal to execution contains four critical transition points where semantic divergence could occur:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   TOCTOU MITIGATION PIPELINE                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

  [ PROPOSAL ] ──(JCS/AST)──► [ AUTHORIZATION ] ──(Hash Bind)──► [ APPROVAL ] ──(Zero Copy)──► [ EXECUTION ]
```

### Potential TOCTOU Divergence Points & Controls

1. **Between Parsing and Authorization:**
   * *Threat:* Dynamic JSON field reordering or floating point precision changes between raw MCP payload and Cedar evaluation.
   * *Mitigation:* Inbound payload is canonicalized once via RFC 8785 (JCS) and AST parsers. The resulting `CanonicalActionPayload` and its SHA-256 `ActionHash` become immutable.
2. **Between Authorization and Human Approval:**
   * *Threat:* Agent submits new tool call while human approval prompt is pending, attempting to execute unapproved parameters.
   * *Mitigation:* The approval prompt on `/dev/tty` explicitly presents the `ActionHash` and canonical diff. When the operator presses 'Y', the generated `Approval` token is cryptographically bound to that exact `ActionHash`.
3. **Between Approval and Credential Acquisition:**
   * *Threat:* Lease token requested for Tool A is used to execute Tool B.
   * *Mitigation:* `CredentialBroker` validates that the `ActionId` matches the approved `Action` aggregate and burns the authorization ticket atomically upon retrieval.
4. **Between Credential Injection and Execution:**
   * *Threat:* Payload re-serialized or modified before network dispatch.
   * *Mitigation:* In-memory Rust architecture ensures zero serialization between Cedar evaluation and native connector execution. The exact struct pointer (`Arc<CanonicalActionPayload>`) is executed.

---

## 7. Adversarial Bypass Model

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       ADVERSARIAL BYPASS MATRIX                                        │
├──────────────────────────┬───────────────────┬─────────────────────────────────────────────────────────┤
│ VECTOR                   │ CLASSIFICATION    │ MITIGATION / ARCHITECTURAL BOUNDARY                     │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Direct Network**       │ REQUIRES OS       │ If agent executes raw shell on host, it can make direct │
│                          │ SANDBOX           │ network calls. Relay requires network namespace isol.   │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Direct Filesystem**    │ REQUIRES OS       │ Agent executing arbitrary bash can read user disk. Host │
│                          │ SANDBOX           │ filesystem permissions and micro-VM sandbox required.   │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Alternate MCP Endpt**  │ PREVENTED         │ Relay enforces fixed stdio routing; agent cannot dynamically│
│                          │                   │ alter server connection targets.                        │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Malicious MCP Server** │ PREVENTED         │ Server schemas are sanitized; tool descriptions stripped;│
│                          │                   │ tool names strictly namespaced; credentials withheld.   │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Child Process Spawn**  │ PREVENTED         │ MCP subprocesses spawned in isolated process groups     │
│                          │                   │ with cleared environment variables.                     │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Symlink Traversal**    │ PREVENTED         │ All filesystem paths canonicalized via `std::fs` before │
│                          │                   │ Cedar policy evaluation.                                │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Path Traversal (..)**  │ PREVENTED         │ Path normalizer strips relative traversals before Cedar.│
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **SQL Ambiguity/Comment**│ PREVENTED         │ SQL payloads parsed into normalized AST (`sqlparser-rs`)|
│                          │                   │ before Cedar parameter matching.                        │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **DNS Rebinding**        │ PREVENTED         │ Egress proxy resolves DNS once and pins target IP for   │
│                          │                   │ the duration of the HTTP connection.                    │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Unix Domain Sockets**  │ PREVENTED         │ UDS permissions restricted to `0600` under user UID.    │
├──────────────────────────┼───────────────────┼─────────────────────────────────────────────────────────┤
│ **Local Host Services**  │ REQUIRES OS       │ Access to `localhost:8080` by unconfined agent code     │
│                          │ SANDBOX           │ requires loopback network firewall rules.               │
└──────────────────────────┴───────────────────┴─────────────────────────────────────────────────────────┘
```

---

## 8. Epistemological Model: Assertions vs. Observations

Relay strictly segregates data claims inside `ActionReceipt` statements into four distinct epistemological categories to maintain audit integrity:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 EPISTEMOLOGICAL DATA CATEGORIES                                  │
├───────────────────────────────┬──────────────────────────────────────────────────────────────────┤
│ 1. Cryptographically Asserted │ Facts Relay signs under its private Ed25519 key (e.g., policy    │
│                               │ evaluation decision, action hash, receipt timestamp, nonce).     │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 2. Relay-Observed             │ Direct physical observations by Relay I/O layer (e.g., HTTP      │
│                               │ status code 200, stdout byte length 412, execution duration 42ms)│
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 3. External State             │ Unverified claims made by third-party APIs (e.g., GitHub body    │
│                               │ content, database returned JSON rows, remote server message).    │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 4. User Assertion             │ Claims made by human operator during approval (e.g., operator    │
│                               │ identity string, interactive approval confirmation).             │
└───────────────────────────────┴──────────────────────────────────────────────────────────────────┘
```

---

## 9. Security Acceptance Criteria & Pre-Build Gate

The Relay MVP implementation cannot be declared complete unless every item in this acceptance gate passes:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECURITY ACCEPTANCE GATE                                       │
├────────┬───────────────────────────────────────────────────┬──────────────┬──────────────────────┤
│ REF    │ CRITERION                                         │ VERIFICATION │ STATUS               │
├────────┼───────────────────────────────────────────────────┼──────────────┼──────────────────────┤
│ SEC-01 │ Zero target credentials in agent memory/env       │ Memory Scan  │ MANDATORY PRE-BUILD  │
│ SEC-02 │ Cedar PDP executes all evaluations deterministically│ Unit Test  │ MANDATORY PRE-BUILD  │
│ SEC-03 │ Denied actions emit zero network/subproc I/O      │ Mock Test    │ MANDATORY PRE-BUILD  │
│ SEC-04 │ ActionHash mismatch aborts execution immediately  │ Fault Inject │ MANDATORY PRE-BUILD  │
│ SEC-05 │ No secrets in SQLite ledger, logs, or receipts    │ Regex Audit  │ MANDATORY PRE-BUILD  │
│ SEC-06 │ Ledger hash-chain tampering detected on verify    │ Corrupt Test │ MANDATORY PRE-BUILD  │
│ SEC-07 │ Path traversals and SQL comments normalized       │ Fuzz Test    │ MANDATORY PRE-BUILD  │
│ SEC-08 │ Memory zeroized on drop for all secret buffers    │ RAII Test    │ MANDATORY PRE-BUILD  │
│ SEC-09 │ MCP subprocesses spawn with `env_clear()`         │ Spawn Test   │ MANDATORY PRE-BUILD  │
│ SEC-10 │ Fail-closed on all panic / timeout / error states │ Chaos Test   │ MANDATORY PRE-BUILD  │
└────────┴───────────────────────────────────────────────────┴──────────────┴──────────────────────┘
```

---

## 10. Summary Conclusions & Contract Sign-Off

* **Security Invariants:** Eighteen (18) formal invariants (SI-001 through SI-018) govern the architecture.
* **Trust Assumptions:** The Agent is **UNTRUSTED**; Relay, Cedar, and Keyring are **TRUSTED (TCB)**; Third-Party MCP servers and Upstream APIs are **PARTIALLY TRUSTED**.
* **Required Controls:** RFC 8785 JCS canonicalization, AST parsers, Cedar ABAC, JIT credential leasing, `/dev/tty` direct approval binding, Ed25519 DSSE signing, and append-only hash-chained SQLite ledger.
* **Residual Risks:** Direct host network/filesystem access by unconfined code-executing agents (mitigated by explicit OS sandbox requirements).
* **Non-Guarantees:** Relay does not guarantee prevention of internal LLM hallucination or prompt injection in agent memory; Relay guarantees **complete deterministic prevention of unauthorized real-world action execution and credential theft**.
