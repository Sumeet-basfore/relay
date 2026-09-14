# Engineering Record: B011 — Approval Provider and Headless Gate

**Status:** Completed  
**Milestone:** B011  
**Author:** Implementation Engineer  
**Date:** 2026-09-14  
**Workspace:** `relay`

---

## 1. Executive Summary

Milestone B011 completes Relay's human-in-the-loop (HITL) authorization subsystem by implementing the **Interactive TTY Approval Provider** and **Headless Fail-Closed Gate**.

Prior to B011, Cedar policy evaluations resulting in `APPROVAL_REQUIRED` terminated immediately with a static error code (`-32005`). With B011:
1. **Interactive TTY Provider:** Evaluates `APPROVAL_REQUIRED` decisions interactively on `/dev/tty` (or Windows `CONIN$/CONOUT$`), strictly isolated from MCP protocol streams (stdin/stdout).
2. **Safe Prompt Rendering & Secret Redaction:** Prompts recursively redact vaulted credential references, bearer tokens, passwords, and private keys into `[VAULTED]`, while prominently displaying the exact cryptographic `ActionHash`, principal, target resource, action identity, and countdown TTL.
3. **Strict State Machine & Ephemeral Binding (SI-004):** Approvals strictly enforce immutable `ActionHash` equivalence (`approved.action_hash == execution.action_hash`), principal, resource, and tool matching. Expired, cancelled, or denied approvals reject terminal execution.
4. **Ordering Invariant:** `CanonicalAction -> Cedar Policy Engine -> APPROVAL_REQUIRED -> Human Approval -> CredentialBroker -> Execution`. The `JitCredentialBroker` categorically refuses lease acquisition for `APPROVAL_REQUIRED` until valid human approval promotes the effective decision state to `Allow`.
5. **Headless Gate (Fail-Closed):** In non-interactive environments (CI/CD, cron, detached containers, or `--non-interactive`), Relay deterministically fails closed with standard exit code `7` (`EXIT_APPROVAL_REQUIRED`) and machine-readable JSON-RPC error payload.

Additionally, as part of the mandatory preflight audit, all B010 filesystem mutation classifications were audited and verified, ensuring atomic rename target errors are classified as deterministic known failures rather than ambiguous outcomes.

---

## 2. Preflight Audit: Filesystem Ambiguity Classification (B010 Follow-up)

An architectural audit of `crates/relay-connectors/src/fs/` was conducted to verify that failures occurring during atomic filesystem mutations are correctly classified:

| Operation | Implementation Mechanism | Failure Stage | Classification | Rationale |
|:---|:---|:---|:---|:---|
| `write_file_atomic` | Write to hidden temp file, sync, then `fs::rename` | Temp write, sync, or pre-rename | `FsError::IoError` (Known Target Failure) | Destination file is untouched; temp file is cleaned up. |
| `write_file_atomic` | Atomic OS rename (`rename(2)`) | Destination rename failure | `FsError::IoError` (Known Target Failure) | POSIX `rename` guarantees atomic replacement; destination is either previous state or new state. |
| `append_file` | Direct in-place append with seek and write | Mid-stream I/O error / timeout | `FsError::AmbiguousMutationOutcome` | Partial bytes may have been written to disk before failure. |
| `remove_directory` | Non-empty directory removal (`fs::remove_dir`) | Directory not empty | `NonRetryableFatal` | Directory was not deleted and remains untouched; outcome is deterministic. |

Regression tests were integrated in `crates/relay-connectors/tests/fs_security_tests.rs` (`test_audit_write_atomic_failure_is_known_not_ambiguous` and `test_sec_25_target_failure_receipt_generation_and_known_error_classification`).

---

## 3. Architecture and Design Decisions

### 3.1 Three-Way Stream Separation

Relay enforces physical isolation between protocol, governance, and diagnostic channels:
- **`stdin` / `stdout`:** Exclusively dedicated to framed JSON-RPC 2.0 MCP protocol messages exchanged with the agent/client and child tool subprocess.
- **`/dev/tty` (`CONIN$` / `CONOUT$` on Windows):** Exclusively dedicated to interactive human operator approval sessions. Prompt rendering and keyboard input bypass stdio completely.
- **`stderr`:** Exclusively dedicated to structured diagnostic tracing (`tracing::info`, `tracing::warn`, `tracing::error`).

```
┌─────────────────────────────────────────────────────────────┐
│                         AI AGENT                            │
└──────────────────────────────┬──────────────────────────────┘
                               │ MCP stdio (stdin / stdout)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                          RELAY                              │
│                                                             │
│  [MCP Gateway] ────> [Canonicalizer] ────> [Cedar PEP]       │
│                                                 │           │
│                                       APPROVAL_REQUIRED     │
│                                                 │           │
│  ┌───────────────────────┐                      ▼           │
│  │ Diagnostics (stderr)  │           [Approval Provider]    │
│  └───────────────────────┘             │           │        │
│                                  Interactive    Headless    │
│                                        │           │        │
│                                        ▼           ▼        │
│                                    /dev/tty   Fail-Closed   │
│                                   (exit code 7 on headless) │
│                                        │                    │
│                                    [Approved]               │
│                                        │                    │
│                                        ▼                    │
│                             [JIT Credential Broker]         │
│                                        │                    │
│                                        ▼                    │
│                              [Native Connector]             │
│                                        │                    │
│                                        ▼                    │
│                             [Signed Action Receipt]         │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Concurrency Serialization via TTY Mutex

To prevent concurrent background tasks from corrupting or interleaving prompts on the controlling terminal, `TtyApprovalProvider` wraps terminal access inside an asynchronous `tokio::sync::Mutex<()>`. When multiple approval requests arrive concurrently, they serialize through the terminal sequentially.

### 3.3 Safe Approval Screen & Secret Redaction

Human operators must be provided with complete context without leaking credentials. `relay-mcp::approval::prompt`:
- Recursively traverses argument JSON structures.
- Replaces any key matching secret patterns (`password`, `secret`, `token`, `key`, `auth`, `credential`, `bearer`, `cookie`, `private`, `sig`) with `"[VAULTED]"`.
- Replaces strings matching private key headers or GitHub PAT prefixes (`ghp_`, `github_pat_`) with `"[VAULTED]"`.
- Formats parameters in readable syntax and computes time-to-live countdown.

### 3.4 Headless Gate (Fail-Closed)

When running in non-interactive mode (`--non-interactive` or headless environments where `/dev/tty` cannot be opened), `HeadlessApprovalGate`:
- Denies the approval request with `ApprovalError::NonInteractiveMode`.
- Emits structured diagnostic warning to stderr.
- Returns JSON-RPC custom error code `-32005` containing machine-readable `exit_code: 7`.

---

## 4. Standard Exit Codes (A007 / A010)

Implemented in `crates/relay-domain/src/exit_code.rs`:

| Code | Constant | Meaning |
|:---|:---|:---|
| `0` | `EXIT_SUCCESS` | Successful execution / audit verification passed |
| `1` | `EXIT_RUNTIME_ERROR` | Runtime error / unhandled execution fault |
| `2` | `EXIT_CONFIG_ERROR` | Configuration error / invalid TOML or flags |
| `3` | `EXIT_POLICY_DENIED` | Policy denied by Cedar engine |
| `4` | `EXIT_APPROVAL_DENIED` | Human operator rejected approval request |
| `5` | `EXIT_PROTOCOL_ERROR` | MCP JSON-RPC protocol violation |
| `6` | `EXIT_SECURITY_FAILURE` | Security invariant violated (tampering, digest mismatch) |
| `7` | `EXIT_APPROVAL_REQUIRED` | Action requires approval but running in headless mode |
| `8` | `EXIT_APPROVAL_EXPIRED` | Approval request timed out before response |
| `9` | `EXIT_APPROVAL_CANCELLED` | Operator cancelled or aborted approval prompt |

---

## 5. Domain Models and State Transitions

### 5.1 Approval State Transitions

`crates/relay-domain/src/approval.rs`:
```
              ┌───────────────┐
              │    Pending    │
              └───────┬───────┘
                      │
       ┌──────────────┼──────────────┬──────────────┐
       │              │              │              │
       ▼              ▼              ▼              ▼
┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐
│   Approved   ││    Denied    ││   Expired    ││  Cancelled   │
│  (Terminal)  ││  (Terminal)  ││  (Terminal)  ││  (Terminal)  │
└──────────────┘└──────────────┘└──────────────┘└──────────────┘
```

- Transitions from terminal states (`Approved`, `Denied`, `Expired`, `Cancelled`) to any other state return `DomainError::InvalidStateTransition`.
- `validate_binding`: Verifies that `state == Approved`, `now <= expires_at`, `action_hash == approved.action_hash`, and matching principal, resource, and action identity (SI-004).

---

## 6. Governed Connectors Integration

The native connectors (`GithubConnector`, `PostgresConnector`, `FilesystemConnector`) enforce step-up human approval at execution time:
- In `execute_governed_with_approval` and `execute_governed_with_receipt`:
  - If `decision.decision == PolicyDecisionType::ApprovalRequired`:
    - Checks that an `Approval` is provided.
    - Validates that `approval.action_hash == canonical_action.action_hash`.
    - Validates that `approval.state == ApprovalState::Approved` and `!approval.is_expired()`.
    - Derives an `effective_decision` (`decision = Allow`) passed to `credential_broker.acquire_lease` and receipt generation.
  - If no approval or an invalid/denied/expired approval is provided, execution immediately fails closed with `UnauthorizedExecution`.

---

## 7. Verification and Testing

### 7.1 Test Suites

| Suite | File | Tests | Focus | Status |
|:---|:---|:---:|:---|:---:|
| Approval Domain Unit Tests | `crates/relay-mcp/tests/approval_unit_tests.rs` | 8 | State transitions, terminal locking, binding validation, expiration, recursive redaction | PASS |
| Interactive TTY Tests | `crates/relay-mcp/tests/approval_tty_tests.rs` | 7 | Approve ('y'), deny ('n'), cancel ('q'), details ('d'), invalid input retry, EOF, timeout | PASS |
| Headless Gate Tests | `crates/relay-mcp/tests/approval_headless_tests.rs` | 1 | Headless fail-closed, exit code 7, diagnostic fields | PASS |
| Gateway E2E Integration | `crates/relay-mcp/tests/gateway_approval_integration.rs` | 3 | Subprocess tool call approved and executed, denied with -32001, headless blocked with -32005 | PASS |
| Ordering & Security Invariant Tests | `crates/relay-connectors/tests/approval_ordering_security_tests.rs` | 7 | Strict ordering, broker rejection without approval, ActionHash mismatch attack, receipt binding | PASS |
| Filesystem Security Audit Tests | `crates/relay-connectors/tests/fs_security_tests.rs` | 27 | Atomic write known failure classification, non-empty directory retry safety, traversal checks | PASS |

### 7.2 Verification Gates

```bash
cargo test --workspace
# Result: 100% PASS across all crates (relay-domain, relay-canonical, relay-credentials, relay-policy, relay-receipts, relay-mcp, relay-ledger, relay-connectors, relay-cli)

cargo clippy --workspace --all-targets -- -D warnings
# Result: 0 errors, 0 warnings

cargo fmt --all -- --check
# Result: Clean formatting across all files
```

---

## 8. Cryptographic Guarantees & Non-Guarantees

### 8.1 Guarantees (SI-004)
1. **Interactive Approval Guarantee:** The human operator physically interacting with the controlling terminal approved the exact displayed `ActionHash`.
2. **Cryptographic Binding:** An approval granted for Action $A$ can never be utilized to execute Action $B$. Any modification to arguments, tool identity, principal, or target resource alters the `ActionHash` and fails binding validation.
3. **Fail-Closed Default:** If terminal I/O encounters an error, reaches EOF, times out, or runs headless, Relay fails closed and blocks execution.
4. **Credential Isolation:** Ephemeral credential leases are never issued for actions requiring approval until the approval is formally granted.

### 8.2 Non-Guarantees
1. Relay does **not** authenticate enterprise SSO identity (no Okta, OAuth, Active Directory, or Kerberos) at this layer.
2. Relay does **not** support remote chat approvals (Slack, Microsoft Teams, Discord). All approvals require local terminal access.
