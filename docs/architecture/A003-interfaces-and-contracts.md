# A003: Relay MVP Interfaces and Rust Implementation Contracts

**Document ID:** `A003-interfaces-and-contracts`  
**Date:** September 2026  
**Status:** Approved Architectural Contract / Implementation Specification  
**Target:** Relay MVP Rust Implementation (`relay-core`, `relay-mcp`, `relay-policy`, `relay-ledger`)  
**Author:** Principal Rust API Architect  
**Corpus Dependencies:** `A001-system-architecture`, `A002-domain-model`, `R015-build-gate`  

---

## Executive Summary

This document establishes the binding interface and type-level contract between the system architecture (`A001`), the canonical domain model (`A002`), and the concrete Rust implementation of Relay.

It specifies:
1. **Precise Module & Subsystem Boundaries:** Explicit ownership, inputs, outputs, and negative boundaries ("must not know about").
2. **Rust Trait Discipline:** Deliberate abstraction boundaries, rejecting speculative traits in favor of concrete types where polymorphism adds no value.
3. **The Governed Request Pipeline:** Type-state transitions from raw incoming JSON-RPC frames to tamper-evident ledger entries.
4. **Compile-Time Security Invariants:** Type-state capabilities (`AuthorizedAction<T>`), affine credential leases, and zeroized memory wrappers preventing unauthorized execution or secret leakage.
5. **A Non-Leaking Error Taxonomy:** Strict segregation of client-facing JSON-RPC errors, internal diagnostic logs, and tamper-evident receipt records.

---

## 1. Architectural Module Boundaries

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   RELAY MODULE TOPOLOGY & BOUNDARIES                             │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

   [ UNTRUSTED INGRESS ]
   ┌────────────────────────────────────────────────────────────────────────────────────────────┐
   │ Transport (Stdio / Named Pipe) ──► Request Parser ──► Canonicalizer (RFC 8785 + AST)       │
   └────────────────────────────────────────────────┬───────────────────────────────────────────┘
                                                    │
                                                    ▼
   [ TRUSTED COMPUTING BASE: GOVERNANCE & POLICY ]
   ┌────────────────────────────────────────────────────────────────────────────────────────────┐
   │ Policy Engine (AWS Cedar PDP) ◄───► Approval Engine (Direct TTY / Passkey / RPC)           │
   │                              │                                                             │
   │                              ▼                                                             │
   │                 AuthorizedAction<State> Token (Type-State Capability)                      │
   │                              │                                                             │
   │                              ▼                                                             │
   │ Credential Broker ◄──────────┴──────────► Execution Dispatcher                             │
   │ (Zeroized Secret Leases)                  │                                                │
   └───────────────────────────────────────────┼────────────────────────────────────────────────┘
                                               │
                                               ├───────────────────────────────┐
                                               ▼                               ▼
   [ TRUSTED EXECUTION TRACKS ]       ┌────────────────────────┐      ┌─────────────────────────┐
                                      │ Native Connector       │      │ External MCP Runtime    │
                                      │ (In-Process GitHub/PG) │      │ & Outbound Egress Proxy │
                                      └────────────┬───────────┘      └────────────┬────────────┘
                                                   │                               │
                                                   └───────────────┬───────────────┘
                                                                   │
                                                                   ▼
   [ TAMPER-EVIDENT EVIDENCE & STORAGE ]              ┌─────────────────────────┐
                                                      │ Receipt Engine (DSSE)   │
                                                      │ & Signer (Ed25519)      │
                                                      └────────────┬────────────┘
                                                                   │
                                                                   ▼
                                                      ┌─────────────────────────┐
                                                      │ Ledger (SQLite / WAL)   │
                                                      └─────────────────────────┘
```

### 1.1 Module Boundary Specifications

| Module Name | Owns | Consumes | Produces | Must NOT Know About | Security Responsibilities |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Transport** | Stdio streams, frame reading/writing, OS pipe buffers. | Raw OS I/O bytes. | `RawFrame` (Bytes / UTF-8 lines). | MCP semantics, JSON schemas, Cedar policies, secrets. | Handle EOF, prevent buffer exhaustion DoS (max frame size 4MB). |
| **Request Parser** | JSON-RPC 2.0 protocol validation, frame deserialization. | `RawFrame`. | `ParsedRpcRequest` (Typed method + unvalidated JSON value). | Policy rules, credentials, execution mechanics. | Reject malformed JSON-RPC, validate 2.0 compliance, enforce schema limits. |
| **Canonicalizer** | Parameter normalization, JCS encoding (RFC 8785), domain AST normalizers. | `ParsedRpcRequest`, `ToolRegistry`. | `NormalizedRequest`, `ActionHash`. | Transport protocol, Cedar DSL specifics, credentials, SQLite. | Enforce deterministic hashing; collapse whitespace/path traversals/SQL AST drift. |
| **Policy Engine** | Embedded AWS Cedar runtime, compiled policy store, schema definitions. | `AuthorizationRequest` (Principal, Action, Resource, Context). | `PolicyDecision` (`Allow`, `Deny`, `ApprovalRequired`). | Raw stdio framing, target credentials, database execution, SQLite. | Deterministic boolean evaluation; fail-closed default deny; enforce invariants. |
| **Approval Engine** | TTY interaction (`/dev/tty`), approval sessions, approver signatures. | `ActionHash`, `ApprovalRequest`, Human TTY inputs. | `Approval` (Decision, Approver ID, Timestamp, Sig). | Target network protocol, credential storage, MCP wire format. | Isolate prompt from agent stdio; bind approval strictly to canonical `ActionHash`. |
| **Credential Broker** | Hardware Keyring, encrypted master store, in-memory JIT token vending. | `AuthorizedAction<WithCredential>`, Keyring API. | `EphemeralLease<T>` (Zeroizing secret wrapper). | Agent identity prompts, MCP frame encoding, SQLite ledger queries. | Zeroize secrets on drop; pin memory (`mlock`); never leak keys in `Debug`/logs. |
| **Native Runtime** | In-process connector implementations (GitHub API, PostgreSQL, FS). | `AuthorizedAction<Executing>`, `EphemeralLease<T>`. | `RawExecutionOutput` (Stdout, Stderr, ExitCode, Bytes). | MCP JSON-RPC framing, TTY approvals, Cedar policy syntax. | Execute strictly authorized actions; sanitize target outputs; handle timeouts. |
| **External Runtime** | Child OS process lifecycle (`tokio::process`), stdio pipes, stripped env. | Tool configuration, sanitized subprocess args. | Child process handle, stdio proxy streams. | Vaulted root credentials, Cedar ASTs, ledger implementation. | Strip all ambient credentials from subprocess `env`; enforce sandbox limits. |
| **Egress Proxy** | Local loopback HTTP proxy (`127.0.0.1:<port>`), wire credential injection. | Subprocess HTTP requests, `EphemeralLease<T>`. | Authenticated upstream HTTP requests & responses. | Agent prompt context, Cedar policy text, SQLite schema. | Inject JIT tokens on wire; reject requests not matching active action lease. |
| **Receipt Engine** | in-toto Statement v1.0 assembly, DSSE envelope wrapping. | `ExecutionRecord`, `Approval`, `PolicyDecision`. | `ActionReceipt` (Unsigned statement). | Network sockets, Keyring storage, TTY handling. | Construct deterministic attestation linking proposal, auth, and execution evidence. |
| **Signer** | Ed25519 signing keypair, DSSE cryptographic signing. | `ActionReceipt` statement bytes. | `SignedActionReceipt` (DSSE JSON). | Tool execution mechanics, Cedar policy syntax. | Protect private key in memory; generate non-repudiable RFC 9598 signatures. |
| **Ledger** | SQLite database connection (`.relay/ledger.db`), hash-chain tracking. | `SignedActionReceipt`. | `LedgerEntry` (Sequence number, Merkle/chain hash). | MCP wire framing, live credential memory buffers. | Ensure atomic, append-only persistence; enforce hash-chain integrity ($O(1)$ verify). |
| **Configuration** | File loading (`relay.toml`), schema validation, CLI overrides. | Configuration files, environment variables, CLI flags. | `RelayConfig` (Validated immutable config). | Runtime session state, live credential bytes. | Validate policy paths, tool registrations, and security parameters at startup. |
| **CLI / Main** | Process entrypoint, Tokio runtime setup, command routing, shutdown. | CLI args (`clap`), OS signals (`SIGINT`, `SIGTERM`). | Process exit code. | Concrete internal connector implementation details. | Orchestrate clean startup/teardown; flush pending ledger transactions on exit. |
| **Verification** | Offline verification engine (`relay verify`). | SQLite ledger file, public key. | Verification report (Chain integrity, signature validity). | Live network, MCP runtime, JIT credential broker. | Mathematically verify receipt signatures, hash-chains, and policy compliance. |

---

## 2. Rust Trait Boundaries: Precision vs. Over-Abstraction

Relay strictly avoids "trait bloat." Traits are introduced **only** where polymorphism, testing substitution, or security isolation demands an abstraction boundary.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   TRAIT BOUNDARY EVALUATION MATRIX                               │
├───────────────────────┬──────────────┬───────────────────────────────────────────────────────────┤
│ Abstraction Candidate │ Decision     │ Architectural Rationale                                   │
├───────────────────────┼──────────────┼───────────────────────────────────────────────────────────┤
│ `PolicyEngine`        │ **TRAIT**    │ Enables mock policy engines in tests; isolates Cedar.    │
│ `CredentialProvider`  │ **TRAIT**    │ Supports Keyring, Env, AWS STS, Vault backends.           │
│ `Connector`           │ **TRAIT**    │ Dynamic dispatch across Native tools (GitHub, Postgres). │
│ `ApprovalProvider`    │ **TRAIT**    │ Supports TTY, Headless auto-deny, and WebAuthn providers. │
│ `ReceiptSigner`       │ **TRAIT**    │ Allows Ed25519 in-memory, PKCS#11 HSM, or KMS backends.   │
│ `ReceiptStore`        │ **TRAIT**    │ Decouples receipt generation from SQLite persistence.     │
│ `McpGateway`          │ **REJECTED** │ Single concrete implementation over Tokio Stdio.          │
│ `Canonicalizer`       │ **REJECTED** │ Deterministic pure function; trait adds zero value.       │
│ `CredentialBroker`    │ **REJECTED** │ Core security state machine; must not be mocked or varied.│
│ `ExecutionEngine`     │ **REJECTED** │ Concrete dispatcher managing Native vs Subprocess tracks. │
│ `Ledger`              │ **REJECTED** │ Concrete SQLite append-only writer backed by dedicated tx.│
│ `ToolRegistry`        │ **REJECTED** │ Concrete in-memory lookup table of registered schemas.    │
└───────────────────────┴──────────────┴───────────────────────────────────────────────────────────┘
```

### 2.1 Accepted Core Trait Definitions

```rust
use async_trait::async_trait;
use std::sync::Arc;
use crate::domain::*;
use crate::error::*;

/// Evaluates deterministic authorization requests against policies.
#[async_trait]
pub trait PolicyEngine: Send + Sync + 'static {
    async fn evaluate(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<PolicyDecision, PolicyError>;

    fn policy_version_hash(&self) -> PolicyVersionHash;
}

/// Fetches raw credentials from a secure storage backend.
#[async_trait]
pub trait CredentialProvider: Send + Sync + 'static {
    async fn resolve_credential(
        &self,
        binding: &CredentialBinding,
    ) -> Result<ResolvedCredential, CredentialError>;
    
    fn provider_name(&self) -> &'static str;
}

/// Executes a specific native tool action within the Relay process.
#[async_trait]
pub trait Connector: Send + Sync + 'static {
    fn tool_name(&self) -> &ToolName;
    
    async fn execute(
        &self,
        action: &AuthorizedAction<StateExecuting>,
        lease: Option<&CredentialLeaseGuard>,
    ) -> Result<ExecutionResult, ExecutionError>;
}

/// Obtains human confirmation when a policy evaluates to APPROVAL_REQUIRED.
#[async_trait]
pub trait ApprovalProvider: Send + Sync + 'static {
    async fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError>;
}

/// Signs in-toto attestation statements using a private cryptographic key.
pub trait ReceiptSigner: Send + Sync + 'static {
    fn key_id(&self) -> &KeyId;
    fn algorithm(&self) -> SignatureAlgorithm;
    fn sign(&self, statement_bytes: &[u8]) -> Result<SignatureBytes, SigningError>;
}

/// Appends and queries signed receipts in immutable storage.
#[async_trait]
pub trait ReceiptStore: Send + Sync + 'static {
    async fn append_receipt(
        &self,
        receipt: SignedActionReceipt,
    ) -> Result<LedgerEntry, PersistenceError>;

    async fn get_receipt(
        &self,
        receipt_hash: &ReceiptHash,
    ) -> Result<Option<SignedActionReceipt>, PersistenceError>;
}
```

---

## 3. Core Request Pipeline & Type Flow

The Relay request pipeline is modeled as an **Affine Type-State Pipeline**. State transitions consume previous values by value, making out-of-order execution, bypass of authorization, or replay impossible at compile time.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AFFINE TYPE-STATE PIPELINE                                     │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│   RawFrame (Bytes)                                                                               │
│      │                                                                                           │
│      ▼ `RequestParser::parse()`                                                                  │
│   ParsedRpcRequest (Unvalidated JSON-RPC)                                                        │
│      │                                                                                           │
│      ▼ `Canonicalizer::normalize()`                                                              │
│   NormalizedRequest (JCS JSON + Canonical AST + ActionHash)                                      │
│      │                                                                                           │
│      ▼ `AuthorizationRequest::from_parts()`                                                      │
│   AuthorizationRequest (Principal, Tool, Resource, CanonicalParams, Context)                     │
│      │                                                                                           │
│      ▼ `PolicyEngine::evaluate()`                                                                │
│   PolicyDecision { Allow | Deny | ApprovalRequired }                                             │
│      │                                                                                           │
│      ├─ [Deny] ───────────────► Terminal Error / Denied Receipt                                  │
│      │                                                                                           │
│      ├─ [ApprovalRequired] ──► `ApprovalEngine::request_approval()` ──► `Approval`               │
│      │                                                                    │                      │
│      ▼                                                                    ▼                      │
│   AuthorizedAction<StateAuthorized> (Cryptographic Capability Token) ◄────┘                      │
│      │                                                                                           │
│      ▼ `CredentialBroker::acquire_lease()`                                                       │
│   AuthorizedAction<StateWithLease> + CredentialLeaseGuard (Zeroized Secret)                      │
│      │                                                                                           │
│      ▼ `ExecutionDispatcher::dispatch()` (Transitions to StateExecuting)                        │
│   ExecutionResult (Status, Duration, OutputHash, RawOutput)                                      │
│      │                                                                                           │
│      ▼ `ReceiptEngine::assemble()`                                                               │
│   ActionReceipt (in-toto Statement v1.0)                                                         │
│      │                                                                                           │
│      ▼ `ReceiptSigner::sign()`                                                                   │
│   SignedActionReceipt (DSSE RFC 9598 Envelope)                                                   │
│      │                                                                                           │
│      ▼ `Ledger::append()`                                                                        │
│   LedgerEntry (SequenceNumber, ChainedHash, Committed DB Row)                                    │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Request Pipeline Boundary Matrix

```
┌────────────────────────┬────────────────────────┬───────────┬────────────┬──────────────────┬──────────────┐
│ Input Type             │ Output Type            │ Ownership │ Mutability │ Error Behavior   │ Secrets?     │
├────────────────────────┼────────────────────────┼───────────┼────────────┼──────────────────┼──────────────┤
│ `RawFrame`             │ `ParsedRpcRequest`     │ Consumed  │ Immutable  │ ProtocolError    │ Never        │
│ `ParsedRpcRequest`     │ `NormalizedRequest`    │ Consumed  │ Immutable  │ CanonicalError   │ Never        │
│ `NormalizedRequest`    │ `AuthorizationRequest` │ Borrowed  │ Immutable  │ ValidationError  │ Never        │
│ `AuthorizationRequest` │ `PolicyDecision`       │ Borrowed  │ Immutable  │ PolicyError      │ Never        │
│ `PolicyDecision`       │ `Approval` (Optional)  │ Borrowed  │ Immutable  │ ApprovalError    │ Never        │
│ `PolicyDecision`       │ `AuthorizedAction<S0>` │ Consumed  │ Immutable  │ AuthFailure      │ Never        │
│ `AuthorizedAction<S0>` │ `AuthorizedAction<S1>` │ Consumed  │ Immutable  │ CredentialError  │ In Guard Only│
│ `AuthorizedAction<S1>` │ `ExecutionResult`      │ Consumed  │ Immutable  │ ExecutionError   │ In Flight    │
│ `ExecutionResult`      │ `ActionReceipt`        │ Consumed  │ Immutable  │ ReceiptGenError  │ Never        │
│ `ActionReceipt`        │ `SignedActionReceipt`  │ Consumed  │ Immutable  │ SigningError     │ Never        │
│ `SignedActionReceipt`  │ `LedgerEntry`          │ Consumed  │ Immutable  │ PersistenceError │ Never        │
└────────────────────────┴────────────────────────┴───────────┴────────────┴──────────────────┴──────────────┘
```

---

## 4. Canonical Domain Type System

Every domain identifier and payload in Relay uses strong newtypes, enforcing formatting, immutability, and safety at compile time.

```rust
use std::fmt;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use secrecy::{SecretString, Zeroize};
use chrono::{DateTime, Utc};

// ============================================================================
// 1. OPAQUE IDENTIFIERS & CONTENT-ADDRESSED DIGESTS (NEWTYPES)
// ============================================================================

/// Monotonically sortable, prefixed ULID for Actions (e.g. `act_01J8YV1...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(String);

/// Monotonically sortable, prefixed ULID for Sessions (e.g. `sess_01J8YV1...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

/// Content-addressed SHA-256 digest of RFC 8785 canonicalized parameters.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionHash([u8; 32]);

/// Content-addressed SHA-256 digest of an ActionReceipt statement.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptHash([u8; 32]);

/// SHA-256 digest of the compiled AWS Cedar policy AST.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyVersionHash([u8; 32]);

/// Tool name formatted as `namespace.tool_name` (e.g. `github.create_issue`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ToolName(String);

/// Canonical target Resource URI (e.g. `urn:relay:fs:/workspace/src/main.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceUri(String);

/// Monotonically incrementing sequence number in the SQLite ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SequenceNumber(u64);

// Formatters for Hashes (Hex Display)
impl fmt::Debug for ActionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActionHash(sha256:{})", hex::encode(self.0))
    }
}
impl fmt::Display for ActionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

// ============================================================================
// 2. PRINCIPAL & ACTOR ENTITIES
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Principal {
    User {
        id: String,
        username: String,
    },
    Agent {
        id: String,
        agent_name: String,
        version: String,
        parent_agent: Option<String>,
    },
}

// ============================================================================
// 3. GOVERNED ACTION PROPOSAL & AUTHORIZATION
// ============================================================================

/// An unvalidated, raw action proposed by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    pub session_id: SessionId,
    pub step_index: u64,
    pub tool_name: ToolName,
    pub raw_arguments: serde_json::Value,
    pub traceparent: Option<String>,
}

/// An immutable, RFC 8785 canonicalized action ready for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub step_index: u64,
    pub principal: Principal,
    pub tool_name: ToolName,
    pub resource: ResourceUri,
    pub canonical_arguments: serde_json::Value,
    pub action_hash: ActionHash,
    pub environment: ExecutionEnvironment,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEnvironment {
    pub cwd: String,
    pub platform: String,
    pub is_interactive_tty: bool,
}

// ============================================================================
// 4. POLICY & APPROVAL DECISION TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow {
        policy_id: String,
        policy_hash: PolicyVersionHash,
    },
    Deny {
        reason: String,
        policy_id: String,
        policy_hash: PolicyVersionHash,
    },
    ApprovalRequired {
        policy_id: String,
        policy_hash: PolicyVersionHash,
        prompt_message: String,
        timeout_seconds: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approval_id: String,
    pub action_hash: ActionHash,
    pub approver_id: String,
    pub decision: ApprovalDecision,
    pub approved_at: DateTime<Utc>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected { reason: String },
    TimedOut,
}

// ============================================================================
// 5. TYPE-STATE CAPABILITY TOKEN: `AuthorizedAction<State>`
// ============================================================================

pub struct StateAuthorized;
pub struct StateWithLease;
pub struct StateExecuting;

/// A cryptographic capability token proving that policy authorized execution.
/// The inner request cannot be extracted or altered; it can only transition.
pub struct AuthorizedAction<State> {
    request: AuthorizationRequest,
    decision: PolicyDecision,
    approval: Option<Approval>,
    _state: std::marker::PhantomData<State>,
}

impl AuthorizedAction<StateAuthorized> {
    pub fn new(
        request: AuthorizationRequest,
        decision: PolicyDecision,
        approval: Option<Approval>,
    ) -> Result<Self, SecurityError> {
        // Enforce invariant: Denied decisions can never construct an AuthorizedAction
        match &decision {
            PolicyDecision::Allow { .. } => Ok(Self {
                request,
                decision,
                approval: None,
                _state: std::marker::PhantomData,
            }),
            PolicyDecision::ApprovalRequired { .. } if approval.as_ref().map(|a| &a.decision) == Some(&ApprovalDecision::Approved) => {
                Ok(Self {
                    request,
                    decision,
                    approval,
                    _state: std::marker::PhantomData,
                })
            }
            _ => Err(SecurityError::UnauthorizedActionConstruction),
        }
    }

    pub fn bind_lease(self) -> AuthorizedAction<StateWithLease> {
        AuthorizedAction {
            request: self.request,
            decision: self.decision,
            approval: self.approval,
            _state: std::marker::PhantomData,
        }
    }
}

impl AuthorizedAction<StateWithLease> {
    pub fn start_execution(self) -> (AuthorizedAction<StateExecuting>, AuthorizationRequest) {
        let req_clone = self.request.clone();
        let executing = AuthorizedAction {
            request: self.request,
            decision: self.decision,
            approval: self.approval,
            _state: std::marker::PhantomData,
        };
        (executing, req_clone)
    }
}

// ============================================================================
// 6. EXECUTION RESULTS & PROVENANCE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub output_hash: [u8; 32],
    pub output_preview: serde_json::Value,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
    ExecutionError,
    Timeout,
    Cancelled,
}

/// in-toto Statement v1.0 wrapped in DSSE envelope (RFC 9598).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedActionReceipt {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String, // Base64-encoded canonical in-toto Statement JSON
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String, // Base64-encoded Ed25519 signature
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub sequence_number: SequenceNumber,
    pub session_id: SessionId,
    pub step_index: u64,
    pub receipt_hash: ReceiptHash,
    pub parent_receipt_hash: ReceiptHash,
    pub committed_at: DateTime<Utc>,
}
```

---

## 5. Secret Handling & Ephemeral Memory Safety Contracts

Relay enforces **zero long-lived in-memory secrets** and **zero secret persistence in domain models**.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECRET LIFECYCLE IN MEMORY                                     │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│   [ OS Keyring / AES-GCM File ] ──► Encrypted Storage                                            │
│                                           │                                                      │
│                                           ▼ `CredentialProvider::resolve()`                      │
│                                  `ResolvedCredential` (secrecy::SecretString)                    │
│                                           │                                                      │
│                                           ▼ `CredentialBroker::vend_lease()`                     │
│                                  `CredentialLeaseGuard` (Affine RAII Guard)                      │
│                                           │                                                      │
│                        ┌──────────────────┴──────────────────┐                                   │
│                        ▼                                     ▼                                   │
│            [ Native Rust Connector ]               [ Egress Proxy Wire Injection ]               │
│            Uses secret in TLS stream               Injects `Authorization` header                │
│                        │                                     │                                   │
│                        └──────────────────┬──────────────────┘                                   │
│                                           │                                                      │
│                                           ▼ `Drop::drop()`                                       │
│                        `zeroize::zeroize()` sweeps memory buffer;                                │
│                        Lease counter decrements; pointer freed.                                  │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 The `CredentialLeaseGuard` Contract

```rust
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Secret container for raw tokens.
/// MUST NEVER implement: Debug, Display, Serialize, Deserialize, Clone.
pub struct RawSecretMaterial {
    inner: SecretString,
}

impl RawSecretMaterial {
    pub fn new(secret: String) -> Self {
        Self {
            inner: SecretString::new(secret),
        }
    }

    /// Exposes secret bytes strictly within a transient closure.
    pub fn expose_scoped<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(self.inner.expose_secret())
    }
}

/// RAII Lease Guard. Zeroizes memory and records lease expiration on Drop.
pub struct CredentialLeaseGuard {
    lease_id: String,
    secret: RawSecretMaterial,
    expires_at: DateTime<Utc>,
}

impl CredentialLeaseGuard {
    pub fn new(lease_id: String, secret: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            lease_id,
            secret: RawSecretMaterial::new(secret),
            expires_at,
        }
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn use_secret<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R, CredentialError> {
        if self.is_expired() {
            return Err(CredentialError::LeaseExpired);
        }
        Ok(self.secret.expose_scoped(f))
    }
}

// Explicit Negative Trait Implementations (Compilation Safety)
impl !Clone for RawSecretMaterial {}
impl !Clone for CredentialLeaseGuard {}
```

### 5.2 Types Forbidden From Deriving `Debug`, `Serialize`, or `Clone`

```
┌────────────────────────┬─────────────┬─────────────┬───────────────┬─────────────────────────────┐
│ Type Name              │ Derive Debug│ Derive Clone│ Derive Ser/De │ Rationale                   │
├────────────────────────┼─────────────┼─────────────┼───────────────┼─────────────────────────────┤
│ `RawSecretMaterial`    │ ❌ FORBIDDEN │ ❌ FORBIDDEN │ ❌ FORBIDDEN  │ Raw secret bytes in RAM.    │
│ `CredentialLeaseGuard` │ ❌ FORBIDDEN │ ❌ FORBIDDEN │ ❌ FORBIDDEN  │ RAII affine lease token.    │
│ `ResolvedCredential`   │ ❌ FORBIDDEN │ ❌ FORBIDDEN │ ❌ FORBIDDEN  │ Vault resolution payload.   │
│ `SigningKeypair`       │ ❌ FORBIDDEN │ ❌ FORBIDDEN │ ❌ FORBIDDEN  │ Ed25519 private key bytes.  │
│ `AuthorizationRequest` │ 🟢 ALLOWED   │ 🟢 ALLOWED   │ 🟢 ALLOWED    │ Zero secrets (Canonical args│
│ `ActionReceipt`        │ 🟢 ALLOWED   │ 🟢 ALLOWED   │ 🟢 ALLOWED    │ Public immutable attestation│
└────────────────────────┴─────────────┴─────────────┴───────────────┴─────────────────────────────┘
```

---

## 6. Comprehensive Error Taxonomy & Information Boundary

Relay establishes an explicit **Three-Tier Error Model**:
1. **Agent-Facing Errors (`JsonRpcError`):** Sanitized, standard JSON-RPC 2.0 error payloads. Never reveals internal policy source code, file paths, or cryptographic keys.
2. **Diagnostic Log Errors (`tracing`):** Structured, local developer logs with full stack traces, evaluated Cedar rule IDs, and performance timings.
3. **Receipt Evidence Records (`ActionReceipt.error`):** Structured error summaries committed to the tamper-evident ledger for compliance discovery.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ERROR CLASSIFICATION & BOUNDARY                                │
├────────────────────────────┬─────────────────────────────┬───────────────────────────────────────┤
│ Error Variant              │ Agent-Facing Response       │ Persisted in Receipt?                 │
├────────────────────────────┼─────────────────────────────┼───────────────────────────────────────┤
│ `ProtocolError`            │ JSON-RPC `-32700` (Parse)   │ No (No session context established)   │
│ `ValidationError`          │ JSON-RPC `-32602` (Params)  │ Yes (Marked as rejected proposal)     │
│ `CanonicalizationError`    │ JSON-RPC `-32602` (Params)  │ Yes (Marked as rejected proposal)     │
│ `PolicyDenied`             │ JSON-RPC `-32001` (Forbidden│ Yes (Full policy decision record)     │
│ `ApprovalRejected`         │ JSON-RPC `-32002` (Rejected)│ Yes (Includes approver rejection note)│
│ `ApprovalTimedOut`         │ JSON-RPC `-32003` (Timeout) │ Yes (Marked as approval timeout)      │
│ `CredentialError`          │ JSON-RPC `-32004` (ExecErr) │ Yes (Generic credential failure flag) │
│ `ConnectorError`           │ Tool-Specific JSON error    │ Yes (Downstream exit code + stderr)   │
│ `ExecutionTimeout`         │ JSON-RPC `-32005` (Timeout) │ Yes (Marked as execution timeout)     │
│ `LedgerPersistenceError`   │ Process Panic / Fail-Closed │ N/A (Triggers immediate stream drop)  │
│ `SigningError`             │ Process Panic / Fail-Closed │ N/A (Triggers immediate stream drop)  │
└────────────────────────────┴─────────────────────────────┴───────────────────────────────────────┘
```

### 6.1 Rust Error Enumeration

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayError {
    #[error("MCP Protocol Error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Parameter Normalization Failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),

    #[error("Policy Evaluation Denied: {0}")]
    PolicyDenied(#[from] PolicyError),

    #[error("Human Approval Failed: {0}")]
    Approval(#[from] ApprovalError),

    #[error("Credential Acquisition Failed: {0}")]
    Credential(#[from] CredentialError),

    #[error("Tool Execution Failed: {0}")]
    Execution(#[from] ExecutionError),

    #[error("Ledger Storage Failed: {0}")]
    Persistence(#[from] PersistenceError),

    #[error("Cryptographic Signing Failed: {0}")]
    Signing(#[from] SigningError),

    #[error("Security Invariant Violated: {0}")]
    InvariantViolation(String),
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Action forbidden by policy '{policy_id}': {reason}")]
    Forbidden { policy_id: String, reason: String },

    #[error("Policy evaluation engine error: {0}")]
    EngineFailure(String),
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Secret not found for binding '{0}'")]
    NotFound(String),

    #[error("Active credential lease has expired")]
    LeaseExpired,

    #[error("Hardware keyring backend unavailable")]
    KeyringUnavailable,
}

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Tool execution timed out after {0}ms")]
    Timeout(u64),

    #[error("Subprocess exited with status {0}")]
    NonZeroExit(i32),

    #[error("Target I/O failure: {0}")]
    Io(#[from] std::io::Error),
}
```

---

## 7. Security-Critical Implementation Contracts

### 7.1 The Authorization Contract
```text
Authorize(request: AuthorizationRequest) -> Result<AuthorizedAction<StateAuthorized>, PolicyError>
```
* **Invariant 1:** The `PolicyEngine` must be deterministic. Identical `AuthorizationRequest` bytes must yield identical decisions.
* **Invariant 2:** An `AuthorizedAction` cannot be constructed if the policy evaluates to `Deny`.

### 7.2 The Execution Contract
```text
Execute(action: AuthorizedAction<StateWithLease>, lease: Option<&CredentialLeaseGuard>) -> Result<ExecutionResult, ExecutionError>
```
* **Invariant 1:** It is impossible to call `Execute` without passing an `AuthorizedAction` capability token.
* **Invariant 2:** The `lease` must match the `tool_name` and `resource` bound inside the `AuthorizedAction`.

### 7.3 The Dynamic Linking Approval Contract
```text
Approve(action_hash: ActionHash, human_input: TtyResponse) -> Result<Approval, ApprovalError>
```
* **Invariant 1:** The approval signature must sign the exact 32-byte `ActionHash`.
* **Invariant 2:** Any parameter alteration post-approval yields a different `ActionHash`, causing execution dispatch to reject the action immediately.

### 7.4 The Tamper-Evident Ledger Append Contract
```text
AppendLedger(receipt: SignedActionReceipt) -> Result<LedgerEntry, PersistenceError>
```
* **Invariant 1:** Insertion must be atomic within a single SQLite write transaction.
* **Invariant 2:** `current_receipt_hash` must equal $\text{SHA-256}(\text{ReceiptBytes} \mathbin{\Vert} \text{parent\_receipt\_hash})$.

---

## 8. Execution-Path Abstraction: Native vs. External MCP

Relay unifies **Native Connectors** and **External Subprocesses** behind a single `ExecutionDispatcher`. Policy evaluation and receipt attestation are completely agnostic to the underlying execution track.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   UNIFIED EXECUTION DISPATCHER                                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

                       AuthorizedAction<StateWithLease>
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   ExecutionDispatcher     │
                        └─────────────┬─────────────┘
                                      │
                   Is tool registered as Native or Subprocess?
                                      │
             ┌────────────────────────┴────────────────────────┐
             ▼ (Native In-Process)                             ▼ (External Subprocess)
  ┌─────────────────────────────┐               ┌─────────────────────────────────────┐
  │  NativeConnector::execute() │               │  SubprocessProxy::dispatch()        │
  │  (e.g., reqwest with token) │               │  (stdio JSON-RPC + Egress Proxy)    │
  └──────────────┬──────────────┘               └──────────────────┬──────────────────┘
                 │                                                 │
                 └────────────────────┬────────────────────────────┘
                                      │
                                      ▼
                        RawExecutionOutput & ExitStatus
                                      │
                                      ▼
                             ActionReceipt Engine
```

---

## 9. Dependency Hierarchy & Clean Architecture

Relay enforces a strict, acyclic dependency tree. Domain logic never depends on infrastructure, storage, or transport.

```
       ┌────────────────────────────────────────────────┐
       │                relay-domain                    │
       │  (Entities, Value Objects, Types, Newtypes)    │
       └───────────────────────▲────────────────────────┘
                               │
       ┌───────────────────────┴────────────────────────┐
       │                relay-policy                    │
       │  (Cedar PDP Engine, Authorization Request/Dec) │
       └───────────────────────▲────────────────────────┘
                               │
       ┌───────────────────────┴────────────────────────┐
       │                relay-execution                 │
       │  (Native Connectors, Credential Broker, Leases)│
       └───────────────────────▲────────────────────────┘
                               │
       ┌───────────────────────┴────────────────────────┐
       │                relay-ledger                    │
       │  (DSSE Signer, SQLite Storage, Receipts)       │
       └───────────────────────▲────────────────────────┘
                               │
       ┌───────────────────────┴────────────────────────┐
       │                relay-mcp / CLI                 │
       │  (Stdio Gateway, Transport, Main Entrypoint)   │
       └────────────────────────────────────────────────┘
```

---

## 10. Async, Threading & Concurrency Model

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ASYNC CONCURRENCY ARCHITECTURE                                 │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│   Tokio Worker Threads (I/O & Compute)                                                           │
│   ┌───────────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ [ Stdio Stream Ingress ] ──► Async Task per MCP Tool Call (Spawned on Tokio)             │  │
│   │                                      │                                                    │  │
│   │                                      ▼                                                    │  │
│   │                          `tokio::sync::Mutex<()>` (TTY Gate)                              │  │
│   │                          (Forces sequential interactive human prompts)                    │  │
│   │                                      │                                                    │  │
│   │                                      ▼                                                    │  │
│   │                          `tokio::sync::mpsc::Sender<SignedActionReceipt>`                 │  │
│   │                          (Non-blocking handoff to Ledger Queue)                           │  │
│   └──────────────────────────────────────┼────────────────────────────────────────────────────┘  │
│                                          │                                                       │
│                                          ▼                                                       │
│   Dedicated Ledger Worker Thread (OS Thread)                                                     │
│   ┌───────────────────────────────────────────────────────────────────────────────────────────┐  │
│   │ `tokio::sync::mpsc::Receiver` ──► Synchronous SQLite Write Transaction (WAL Mode)         │  │
│   │ (Guarantees zero write lock contention and atomic sequential hash chaining)              │  │
│   └───────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Tokio Runtime:** Handles high-volume async network requests, subprocess stdio pipes, and timer timeouts.
2. **TTY Gate:** A `tokio::sync::Mutex<()>` serializes human confirmation prompts, preventing terminal output interleaving when agents invoke tools concurrently.
3. **Dedicated SQLite Thread:** All receipt writes are submitted via an unbounded `mpsc` queue to a single, dedicated OS thread holding the SQLite write lock.

---

## 11. API Stability & Versioning

1. **User-Facing CLI (`relay run`, `relay verify`):** Semantic Versioning (`SemVer 2.0`). Breaking CLI flag changes require major version increments.
2. **Action Receipt Schema (`https://relay.dev/attestation/action-receipt/v1`):** Append-only JSON schema evolution. Fields are never removed or renamed without a URI bump to `/v2`.
3. **Internal Rust Interfaces:** Unstable during `0.1.x` MVP; public traits stabilize at `1.0.0`.

---

## 12. End-to-End Contract Examples

### 12.1 Scenario: `ALLOW` (Native Read Action)
```rust
// 1. Ingress parses and canonicalizes
let raw_frame = transport.read_frame().await?;
let parsed = RequestParser::parse(raw_frame)?;
let normalized = Canonicalizer::normalize(parsed, &tool_registry)?;

// 2. Build Authorization Request
let auth_req = AuthorizationRequest::from_parts(&session, normalized)?;

// 3. Policy Evaluation
let decision = policy_engine.evaluate(&auth_req).await?;
assert!(matches!(decision, PolicyDecision::Allow { .. }));

// 4. Construct Type-State Capability Token
let authorized_action = AuthorizedAction::<StateAuthorized>::new(auth_req, decision, None)?;
let leased_action = authorized_action.bind_lease();

// 5. Execute natively
let (executing_action, req) = leased_action.start_execution();
let exec_result = connector.execute(&executing_action, None).await?;

// 6. Generate & Commit Receipt
let receipt = receipt_engine.assemble(&req, &exec_result, None);
let signed_receipt = signer.sign(&receipt)?;
ledger.append(signed_receipt).await?;
```

### 12.2 Scenario: `APPROVAL_REQUIRED` (State-Mutating Postgres Action)
```rust
// 1. Policy evaluates to APPROVAL_REQUIRED
let decision = policy_engine.evaluate(&auth_req).await?;
let prompt = match &decision {
    PolicyDecision::ApprovalRequired { prompt_message, .. } => prompt_message,
    _ => unreachable!(),
};

// 2. Request Interactive Human Confirmation on TTY
let approval_decision = approval_provider.request_approval(&ApprovalRequest {
    action_hash: auth_req.action_hash.clone(),
    message: prompt.clone(),
}).await?;

let approval = Approval {
    approval_id: format!("appr_{}", ulid::Ulid::new()),
    action_hash: auth_req.action_hash.clone(),
    approver_id: "user:sumeet".into(),
    decision: approval_decision,
    approved_at: Utc::now(),
    signature: None,
};

// 3. Construct Capability Token with Validated Approval
let authorized_action = AuthorizedAction::<StateAuthorized>::new(auth_req, decision, Some(approval.clone()))?;
let leased_action = authorized_action.bind_lease();

// 4. Acquire JIT Credential Lease
let lease = credential_broker.acquire_lease(&leased_action).await?;

// 5. Execute with leased credential
let (executing_action, req) = leased_action.start_execution();
let exec_result = connector.execute(&executing_action, Some(&lease)).await?;

// 6. Drop lease (Zeroizes token from memory immediately)
drop(lease);

// 7. Commit full provenance to ledger
let receipt = receipt_engine.assemble(&req, &exec_result, Some(approval));
let signed_receipt = signer.sign(&receipt)?;
ledger.append(signed_receipt).await?;
```

### 12.3 Scenario: `DENY` (Security Invariant Violation)
```rust
// 1. Policy evaluates to Deny
let decision = policy_engine.evaluate(&auth_req).await?;
assert!(matches!(decision, PolicyDecision::Deny { .. }));

// 2. Type-State constructor returns Err; execution is structurally impossible
let err = AuthorizedAction::<StateAuthorized>::new(auth_req.clone(), decision.clone(), None);
assert!(err.is_err());

// 3. Return sanitized JSON-RPC error to untrusted agent
let rpc_err = JsonRpcResponse::error(
    auth_req.action_id,
    -32001,
    "Action forbidden by organization policy",
);
transport.write_response(rpc_err).await?;
```

---

## 13. Summary Reference Checklist

* [x] **Canonical Interfaces Defined:** `PolicyEngine`, `CredentialProvider`, `Connector`, `ApprovalProvider`, `ReceiptSigner`, `ReceiptStore`.
* [x] **Canonical Domain Types Specified:** All 12 entities and 4 value objects defined as strong Rust types.
* [x] **Security-Critical Boundaries Established:** Type-state `AuthorizedAction<State>` prevents unapproved execution.
* [x] **Secret Handling Encapsulated:** `CredentialLeaseGuard` and `RawSecretMaterial` enforce RAII zeroization and deny `Debug`/`Serialize`/`Clone`.
* [x] **Three-Tier Error Model Implemented:** Clear segregation of agent responses, logs, and receipt evidence.
* [x] **Acyclic Architecture Maintained:** Zero coupling between domain, policy, execution, and SQLite infrastructure.
* [x] **Zero Open Conceptual Gaps:** Seamless progression from raw incoming stdio JSON-RPC frame to signed in-toto/DSSE ledger entry.
