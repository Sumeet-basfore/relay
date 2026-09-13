# Milestone B001: Repository, Domain Models, and Foundation

**Status:** Completed  
**Milestone:** B001  
**Target Delivery:** Relay MVP Foundation  
**Specification References:** [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces and Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A008 Rust Dependency Architecture](../architecture/A008-rust-dependency-architecture.md), [A010 Build Specification](../architecture/A010-build-specification.md)

---

## 1. Executive Summary

Milestone `B001` establishes the foundational Rust workspace, domain modeling layer, trait contracts, error taxonomy, zero-trust memory security primitives, configuration hierarchy, and diagnostic CLI for Relay.

In accordance with architectural invariants defined in `A001`–`A010`, this milestone implements:
1. **Workspace Architecture**: Multi-crate Cargo workspace isolating pure domain definitions from transport, cryptography, policy evaluation, storage, and connector execution.
2. **Pure Domain Core (`relay-domain`)**: Strongly typed UUIDv7 entity IDs (`act_`, `sess_`, `dec_`, `appr_`, `lease_`, `exec_`, `rcpt_`), cryptographic digest wrappers (`ActionHash`, `OutputHash`, `Digest`), formal state machine transition enforcement, in-toto attestation predicates, and zeroize-protected secret buffers (`SecretBuffer`).
3. **Core Contracts & Interfaces**: Trait abstractions for `PolicyEngine`, `CredentialBroker`, `ExecutionDispatcher`, `Ledger`, `ReceiptSigner`, `Canonicalizer`, and `NativeConnector`.
4. **Error Hierarchy**: Strongly typed, centralized error taxonomy (`RelayError`, `DomainError`, `ProtocolError`, `CanonicalizationError`, `PolicyError`, `CredentialError`, `ExecutionError`, `ApprovalError`, `LedgerError`, `CryptoError`, `InvariantViolationError`).
5. **Gateway CLI & Diagnostics (`relay-cli`)**: Single-binary entrypoint (`relay`) providing `doctor`, `run`, `policy`, `secret`, `receipt`, and `verify` command structure with structured diagnostic logging and health checks.

---

## 2. Workspace & Crate Structure

The repository is structured as an explicit multi-crate Cargo workspace:

```
relay/
├── Cargo.toml                      # Root workspace definition & centralized dependency versions
├── rustfmt.toml                    # Strict deterministic Rust formatting rules
├── deny.toml                       # Supply chain & license governance (cargo-deny)
├── crates/
│   ├── relay-domain/               # Pure domain models, state machines, errors, traits (no I/O)
│   ├── relay-canonical/            # RFC 8785 JCS canonicalization & resource resolver stubs
│   ├── relay-policy/               # Cedar PDP evaluation contracts & policy engine stubs
│   ├── relay-credentials/          # Ephemeral JIT credential broker contracts & stubs
│   ├── relay-receipts/             # DSSE & in-toto v1.0 receipt signing contracts & stubs
│   ├── relay-connectors/           # Native connector isolation interfaces & stubs (FS, GitHub, PG)
│   ├── relay-mcp/                  # MCP protocol framing & JSON-RPC 2.0 transport models
│   ├── relay-ledger/               # Append-only SQLite ledger interface & in-memory verification
│   └── relay-cli/                  # Unified CLI binary entrypoint, config loader, & diagnostics
├── docs/
│   ├── architecture/               # Frozen architecture specifications (A001 - A010)
│   ├── engineering/                # Implementation milestone tracking (B001)
│   └── research/                   # Problem space research corpus (R001 - R015)
```

---

## 3. Implemented Domain Entities & State Machines

### 3.1 Strongly Typed Identifiers (`id.rs`)
Entities and cryptographic values use distinct, strongly-typed wrappers preventing primitive obsession and identifier cross-contamination:
- **`ActionId`**: `act_<uuidv7>` (Time-ordered UUIDv7)
- **`SessionId`**: `sess_<uuidv7>` (Time-ordered UUIDv7)
- **`DecisionId`**: `dec_<uuidv7>` (Time-ordered UUIDv7)
- **`ApprovalId`**: `appr_<uuidv7>` (Time-ordered UUIDv7)
- **`LeaseId`**: `lease_<uuidv7>` (Time-ordered UUIDv7)
- **`ExecutionId`**: `exec_<uuidv7>` (Time-ordered UUIDv7)
- **`ReceiptId`**: `rcpt_<uuidv7>` (Time-ordered UUIDv7)
- **`ToolId`**: `<namespace>.<tool_name>` (Namespaced identifier)
- **`PrincipalId`**: `principal:<type>:<domain>:<id>` (URN format)
- **`AgentId`**: `agent:<name>:<version>` (URN format)
- **`ActionHash` / `OutputHash` / `Digest`**: SHA-256 32-byte cryptographic hashes

### 3.2 State Machines (`action.rs`, `session.rs`, `approval.rs`, `execution.rs`, `credential.rs`)
State machines enforce strictly validated lifecycle transitions:
- **`ActionState`**: `Proposed` $\rightarrow$ `Authorized` | `AwaitingApproval` | `Rejected` $\rightarrow$ `Approved` $\rightarrow$ `Executing` $\rightarrow$ `Executed` | `ExecutionFailed` $\rightarrow$ `Settled`
- **`SessionState`**: `Created` $\rightarrow$ `Active` $\rightarrow$ `Terminated` $\rightarrow$ `Closed`
- **`ApprovalState`**: `Pending` $\rightarrow$ `Approved` | `Denied` | `Expired` | `Cancelled`
- **`ExecutionState`**: `Pending` $\rightarrow$ `Running` $\rightarrow$ `Succeeded` | `Failed` | `Cancelled` | `TimedOut`
- **`LeaseState`**: `Issued` $\rightarrow$ `Consumed` | `Expired` | `Revoked`

### 3.3 Zero-Trust Secret Containment (`security.rs`)
- **`SecretBuffer`**: Wraps heap-allocated secret credentials, implementing `zeroize::ZeroizeOnDrop` to scrub memory when dropped. Explicitly masks `Debug` (`[REDACTED <N> bytes]`) and `Display` (`[REDACTED SECRET]`) implementations to prevent accidental leakage in logs or telemetry.
- **`RedactedSecret`**: Wraps secret strings with `secrecy::SecretString` protection.

---

## 4. Error Taxonomy & Invariants

The `relay-domain::error` module defines exhaustive error classifications mapping directly to the architecture:
- **`DomainError`**: State transition violations, invalid IDs, entity collision, missing entities.
- **`ProtocolError`**: JSON-RPC parse errors, frame size exceedances, stream disconnections.
- **`ValidationError`**: Missing parameters, schema mismatches, type violations.
- **`CanonicalizationError`**: RFC 8785 JCS sorting errors, filesystem traversal attacks, SQL AST normalization errors.
- **`PolicyError`**: Cedar evaluation errors, schema violations, policy corruption.
- **`CredentialError`**: Lease expiration, provider resolution failures, keyring I/O errors.
- **`ExecutionError`**: Subprocess crashes, native connector failures, timeout exceedances.
- **`ApprovalError`**: Human rejection, approval expiration, device communication errors.
- **`LedgerError`**: Hash chain verification mismatches, disk corruption, sequence number gaps.
- **`CryptoError`**: Ed25519 signing and verification errors, DSSE envelope encoding failures.
- **`InvariantViolationError`**: Software assertions for critical security invariants (`SI-001` through `SI-010`).

---

## 5. Verification & Test Suite

Milestone B001 establishes full test coverage across all domain components and CLI integration:

| Test Suite | Test Focus | Status |
|---|---|---|
| `id_tests.rs` | Strongly typed UUIDv7 IDs, prefixes, URN formatting, serialization, SHA-256 digests | ✅ Passed (5/5) |
| `state_machine_tests.rs` | Action, Session, Approval, Execution, Lease lifecycle transitions, invalid transition rejections | ✅ Passed (8/8) |
| `security_tests.rs` | Memory zeroization, secret buffer redactions, `Debug`/`Display` leakage prevention | ✅ Passed (3/3) |
| `error_tests.rs` | Error hierarchy conversions, JSON-RPC error code mapping, invariant violation errors | ✅ Passed (1/1) |
| `cli_tests.rs` | CLI flag parsing, `--help`, `--version`, `relay doctor` environment diagnostics, milestone stub handling | ✅ Passed (4/4) |

### Test Execution Summary
- **Unit & Integration Tests**: 21 passed, 0 failed, 0 ignored.
- **Code Linter (`cargo clippy --workspace --all-targets -- -D warnings`)**: Clean (0 warnings).
- **Code Formatter (`cargo fmt --check`)**: Clean (0 formatting discrepancies).
- **CLI Diagnostics (`relay doctor`)**: Successfully verifies architecture, OS, working directory, and environment readiness.

---

## 6. Definition of Done (DoD) Verification

- [x] **Workspace created with all 9 crates according to A008 & A010**
- [x] **Pure domain types defined in `relay-domain` with no I/O dependencies**
- [x] **State machine transition enforcement implemented and tested**
- [x] **Cryptographic identifiers and UUIDv7 typed IDs implemented**
- [x] **Memory safety and secret zeroization wrappers implemented**
- [x] **Centralized error taxonomy implemented**
- [x] **Core trait contracts defined for all subsequent milestones**
- [x] **CLI binary and `relay doctor` command operational**
- [x] **All tests passing with 100% clean Clippy and rustfmt runs**
- [x] **Milestone engineering documentation generated in `docs/engineering/B001-foundation.md`**
