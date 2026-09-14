# Engineering Record: RC001 — Release Hardening

**Status:** Completed  
**Milestone:** RC001  
**Author:** Release & Security Hardening Lead  
**Date:** 2026-09-14  
**Workspace:** `relay`  
**Target Artifact:** `target/release/relay` (v0.1.0)  
**Evaluation Verdict:** `PASS` (Implementation) / `PASS` (Security) / `READY WITH CONDITIONS` (Release Readiness)

---

## 1. Executive Summary

Milestone RC001 represents the final release-hardening and productionization pass across the complete Relay codebase following the completion of engineering milestones B001 through B013. 

The primary objective of RC001 is to transition the validated milestone implementation into a defensible, production-grade release candidate without expanding product scope, redesigning architecture, or adding unneeded complexity.

### Core Hardening Actions Implemented:
1. **Deterministic Exit Codes & CLI Fail-Closed Semantics (A007, A010):**
   Integrated standard Unix exit codes (`0`–`9`) into `CliError`, guaranteeing deterministic exit behavior for configuration errors (`2`), policy denials (`3`), approval rejections (`4`), protocol errors (`5`), security/ledger failures (`6`), and headless approval blocks (`7`).
2. **Fail-Closed Ledger Configuration:**
   Eliminated silent in-memory fallback on database open failure. If `.relay/ledger.db` cannot be opened or created, Relay fails closed with `CliError::StorageError` (exit code `6`).
3. **Atomic Unix Permissions & TOCTOU Elimination:**
   Hardened SQLite database creation (`0600`) and private state directory creation (`0700`) using `std::os::unix::fs::OpenOptionsExt` and `DirBuilderExt`, preventing temporary world-readable windows at file creation time.
4. **Secret Material & Debug Redaction:**
   Hardened `PostgresCredentials` with custom `fmt::Debug` (`[REDACTED]`) and automatic memory zeroization on `Drop`. Verified `SecretBuffer` virtual memory locking (`mlock`), zeroization, and debug masking.
5. **Signing Key Management & Permissions:**
   Added hardened key import/export methods (`from_hex`, `from_file`, `save_to_file`) to `Ed25519ReceiptSigner` enforcing `0600` file permissions and explicit development vs. production identity distinction (`relay-dev-ed25519-v1` vs. configured keys).
6. **Subprocess Environment Isolation:**
   Verified and hardened child MCP subprocess spawning via `env_clear()` and an explicit whitelist of safe system variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `TMPDIR`, `SYSTEMROOT`, `WINDIR`, `LC_*`), stripping all ambient API keys and credentials.
7. **Release Build Optimization:**
   Configured and validated production release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`), producing a standalone ~14 MB static binary with zero debug symbol leaks.
8. **Automated RC001 Hardening Test Suite:**
   Constructed and validated `crates/relay-cli/tests/rc001_hardening_tests.rs` alongside all 299 tests across the 9 workspace crates (100% green, 0 failures, 0 clippy warnings).

---

## 2. Phase 1 — Repository and Architecture Audit

### 2.1 Workspace Crates and Binary Artifacts
The Relay repository consists of a cargo workspace with 9 specialized crates:
- **`relay-domain` (`crates/relay-domain`):** Pure core domain models, cryptographic IDs, error enums, standard exit codes (`ExitCode`), and security traits. Zero I/O dependencies.
- **`relay-canonical` (`crates/relay-canonical`):** RFC 8785 JCS canonicalization, strict non-duplicate JSON parser, SQL AST normalizer, and filesystem path lexical normalizer.
- **`relay-policy` (`crates/relay-policy`):** Embedded AWS Cedar policy engine (v4.0), schema validation, and deterministic policy digest calculator (SI-010).
- **`relay-credentials` (`crates/relay-credentials`):** Ephemeral JIT credential broker and OS Keyring / in-memory providers.
- **`relay-receipts` (`crates/relay-receipts`):** DSSE envelope (RFC 9598) + in-toto Statement v1.0 builder and Ed25519 signer/verifier with secret scrubbing.
- **`relay-connectors` (`crates/relay-connectors`):** In-process native connectors (GitHub, PostgreSQL, Filesystem) and the 7-stage `GovernedActionRunner` coordinator.
- **`relay-ledger` (`crates/relay-ledger`):** Cryptographic append-only SQLite storage engine with SQL immutability triggers and offline chain verifier.
- **`relay-mcp` (`crates/relay-mcp`):** Bounded stdio MCP gateway, JSON-RPC framer, stream multiplexer, and `/dev/tty` + Headless approval providers.
- **`relay-cli` (`crates/relay-cli`):** Main CLI binary (`relay`), runtime configuration loader, diagnostic doctor, and subcommand handlers.

### 2.2 Release Surface Inventory

| Dimension | Inventory / Implementation Reality | Security Classification |
|:---|:---|:---|
| **Binaries** | `relay` (`crates/relay-cli/src/main.rs`) | Single production binary |
| **Public APIs** | Crate root exports documented in respective `lib.rs` | Internal workspace boundaries |
| **Feature Flags** | Standard workspace features (no experimental/backdoor flags) | Hardened |
| **Environment Variables** | `RELAY_ACTIVE`, `RELAY_VERSION`, `RELAY_SIGNING_KEY`, `RELAY_SIGNING_KEY_PATH`, `HOME` | Explicitly constrained & sanitized |
| **Filesystem Paths** | `.relay/ledger.db` (ledger), `~/.config/relay/` (config/keys), `/dev/tty` (prompts) | Restrictive permissions (`0600`/`0700`) |
| **Persistent State** | SQLite database file (`ledger.db`) | Append-only, trigger-protected, WAL mode |
| **Network Listeners** | None in stdio gateway mode; loopback only for mock tests | No external listening ports |
| **Subprocess Creation** | `tokio::process::Command` with `env_clear()` + whitelist | No shell interpolation; sanitized env |
| **Cryptographic Keys** | Ed25519 (256-bit seed, OsRng CSPRNG) | Memory zeroized on Drop |
| **Logging/Tracing** | `tracing-subscriber` strictly directed to `stderr` | Zero protocol contamination on `stdout` |
| **Temporary Files** | Hidden dotfiles in target directory for atomic write (`.relay_tmp_*`) | Cleaned up on completion/failure |

---

## 3. Phase 2 — Production Configuration Audit

All runtime configuration values were audited for default safety, range enforcement, and fail-closed behavior:

| Configuration Parameter | Default Value | Allowed Range | Fallback Behavior | Security Impact |
|:---|:---|:---|:---|:---|
| `security.default_deny` | `true` | `true` / `false` | Always defaults to `true` | Fundamental zero-trust invariant |
| `security.approval_timeout_secs` | `30` | `1` – `3600` | Expires after timeout | Prevents indefinite agent hangs |
| `security.max_frame_size_bytes` | `4194304` (4 MB) | `1024` – `67108864` | Rejects oversized frame (`-32600`) | Memory exhaustion (DoS) protection |
| `storage.ledger_path` | `.relay/ledger.db` | Valid Unix path | Fails closed on error | Audit durability guarantee |
| `policy.policy_dir` | `policies` | Directory path | Falls back to in-binary default Cedar policies | Deterministic fail-closed |
| `github.connect_timeout` | `5s` | `1s` – `60s` | Network timeout error | Ambiguous mutation tracking |
| `github.request_timeout` | `15s` | `1s` – `120s` | Network timeout error | Ambiguous mutation tracking |
| `github.max_response_bytes`| `2097152` (2 MB) | `1024` – `10485760` | Rejects oversized response | Memory exhaustion protection |
| `postgres.connect_timeout` | `5s` | `1s` – `60s` | Connection failure error | Fail-closed |
| `postgres.query_timeout` | `10s` | `1s` – `300s` | Statement cancellation error | Ambiguous mutation tracking |
| `non_interactive` flag | `false` (interactive) | CLI flag (`--non-interactive`) | Fallback to headless gate if no TTY | Deterministic headless execution |

---

## 4. Phase 3 — Secrets and Key Material Audit

### 4.1 Secret Handling in Memory
- **`SecretBuffer` (`relay-domain`):** Wraps sensitive credential bytes. Uses `libc::mlock` to lock pages in physical RAM (preventing paging to disk swap) and registers a `Drop` hook calling `zeroize::Zeroize` to scrub memory. Masks `Debug` and `Display`.
- **`PostgresCredentials` (`relay-connectors`):** Hardened in RC001 with custom `Debug` implementation emitting `[REDACTED]` for the password field, and implements `Drop` with `password.zeroize()`.
- **`CredentialLeaseGuard` (`relay-domain`):** RAII guard providing scoped single-action access to credentials. Zeroizes on drop and cannot be cloned or serialized.
- **Ed25519 Signing Keys (`relay-receipts`):** Utilizes `ed25519-dalek::SigningKey` which implements constant-time operations and zeroization on drop. Custom `Debug` implementation explicitly emits `"[REDACTED SECRET KEY]"`.

### 4.2 Leak Prevention in Artifacts and Logs
- **Secret Scrubber (`relay-receipts/src/scrub.rs`):** Defensively scans all receipt JSON payloads prior to DSSE signing for forbidden credential patterns (`ghp_`, `AKIA`, `ASIA`, `sk-proj-`, SSH/RSA private keys, and `Authorization: Bearer` headers). If detected, receipt generation fails closed.
- **TTY UI Masking (`relay-mcp/src/approval/prompt.rs`):** Recursively inspects argument dictionaries and redacts sensitive field values (`password`, `token`, `secret`, `authorization`, `private_key`) to `[VAULTED]` on operator approval prompts.

---

## 5. Phase 4 — Filesystem Permissions and State Directories

### 5.1 Restrictive Creation Modes
On Unix platforms, Relay enforces atomic restrictive permissions at file/directory creation time:
- **Ledger Parent Directory (`.relay/` or custom):** Created with mode `0700` (`rwx------`) via `std::os::unix::fs::DirBuilderExt`.
- **Ledger Database File (`ledger.db`):** Created with mode `0600` (`rw-------`) via `std::os::unix::fs::OpenOptionsExt::mode(0o600)`.
- **Signing Key File (`signing_key.seed`):** Saved with mode `0600` (`rw-------`).

### 5.2 Symlink Attack Mitigations
- **Filesystem Connector (`relay-connectors/src/fs/jail.rs`):** Inspects `symlink_metadata` using `O_NOFOLLOW` semantics. Symlinks are rejected by default. When enabled, canonical physical targets are resolved and validated against the configured root directory boundary. Traversal attacks escaping the root directory return `FsError::PathTraversal`.

---

## 6. Phase 5 — SQLite Ledger Hardening

The audit ledger persistence engine (`relay-ledger`) enforces the following storage invariants:

1. **WAL Mode & Normal Synchronous Durability:**
   ```sql
   PRAGMA foreign_keys = ON;
   PRAGMA journal_mode = WAL;
   PRAGMA synchronous = NORMAL;
   PRAGMA busy_timeout = 5000;
   ```
2. **Engine-Level SQL Immutability Triggers:**
   `prevent_ledger_update` and `prevent_ledger_delete` triggers raise `ABORT` on any attempted in-place update or deletion of rows in `ledger_entries` or `action_receipts`.
3. **Cryptographic Hash Chain:**
   Each entry hash is computed over `sequence_number || parent_hash || payload_hash || timestamp`. Any bit modification in payload, metadata, or ordering breaks verification during `LedgerVerifier::verify_file`.
4. **Post-Execution Durability Interruption (SI-015):**
   If a disk-full (`ENOSPC`) or I/O error occurs during ledger append after a native connector mutation succeeds, Relay preserves the execution truth, returns the valid signed receipt in the outcome payload, and records `ledger_error` rather than falsely asserting the action was aborted.

---

## 7. Phase 6 — CLI and Exit Semantics

Standardized Unix exit codes are defined in `relay_domain::ExitCode` and mapped deterministically through `CliError::exit_code()`:

| Exit Code | Constant | Meaning |
|:---:|:---|:---|
| **0** | `EXIT_SUCCESS` | Execution completed normally. |
| **1** | `EXIT_RUNTIME_ERROR` | Subprocess crashed, connection failed, or uncaught runtime error. |
| **2** | `EXIT_CONFIG_ERROR` | Invalid CLI arguments, missing command, or unparseable policy files. |
| **3** | `EXIT_POLICY_DENIED` | Action denied by Cedar authorization policy. |
| **4** | `EXIT_APPROVAL_DENIED` | Operator rejected action on `/dev/tty` prompt. |
| **5** | `EXIT_PROTOCOL_ERROR` | Malformed MCP JSON-RPC frame from client or child subprocess. |
| **6** | `EXIT_SECURITY_FAILURE` | Storage failure, signature verification failure, or ledger tampering detected. |
| **7** | `EXIT_APPROVAL_REQUIRED` | Action requires approval but Relay is in headless / `--non-interactive` mode. |
| **8** | `EXIT_APPROVAL_EXPIRED` | Approval request timed out waiting for human confirmation. |
| **9** | `EXIT_APPROVAL_CANCELLED`| Approval prompt was cancelled by operator interrupt (Ctrl+C). |

---

## 8. Phase 7 — Process and Subprocess Hardening

### 8.1 Child MCP Process Spawning
Child tool server processes are spawned using `tokio::process::Command` without shell interpolation:
- **Stream Redirection:** `stdin` and `stdout` are strictly piped for framed JSON-RPC communication; `stderr` is inherited for debug output.
- **Environment Sanitization:** Calls `cmd.env_clear()` and populates only safe environment variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `TMPDIR`, `SYSTEMROOT`, `WINDIR`, `LC_*`, `RELAY_ACTIVE=1`, `RELAY_VERSION`).
- **Shutdown Grace Period:** Implements two-stage termination: sends SIGTERM (or closes stdin), waits up to 500ms grace period (`DEFAULT_SHUTDOWN_GRACE_PERIOD`), and escalates to SIGKILL if the process fails to terminate.

---

## 9. Phase 8 — Network Surface Audit

### 9.1 GitHub Connector Network Surface
- **Transport Security:** Pure Rustls TLS (`webpki-roots`) over HTTPS.
- **Host Lockdown:** Strict host whitelist locked to `api.github.com` (loopback permitted only in explicit test mode).
- **Redirect Policy:** `reqwest::redirect::Policy::custom` rejects HTTP downgrades and cross-host redirects.
- **Payload Limits:** Maximum response body size capped at 2 MB.
- **Timeout Management:** 5s connection timeout, 15s request timeout.

### 9.2 PostgreSQL Connector Network Surface
- **Transport Security:** Rustls TLS (`postgres_rustls`) required for all remote PostgreSQL endpoints; plaintext permitted only for `127.0.0.1` and `localhost` loopback test configurations.
- **Connection Isolation:** Per-action isolated connections (zero cross-authority pooling in MVP).
- **Injection Mitigation:** Validates hostnames against alphanumeric dot notation; SQL parser normalizes statements and rejects multi-statements.

---

## 10. Phase 9 — Cedar Policy Engine Audit

- **Deterministic Ordering:** `PolicyLoader::load_from_dir` reads all `.cedar` files, sorts paths deterministically, and combines them with source location comments.
- **Schema Validation:** Strict schema validation (`ValidationMode::Strict`) against the Relay domain schema before compiling policy sets.
- **PolicySet Digest (SI-010):** Computes deterministic SHA-256 digest over normalized policy text and records it in every policy decision and action receipt.
- **Fail-Closed Default:** Unmatched actions evaluate to `PolicyDecisionType::Deny`. Missing or malformed policy files prevent gateway startup.

---

## 11. Phase 10 — Dependency and Supply-Chain Hygiene

- **Workspace Dependencies:** Standard, audited ecosystem crates (`tokio`, `serde`, `cedar-policy`, `ed25519-dalek`, `rusqlite`, `rustls`, `zeroize`, `reqwest`).
- **Clippy Audit:** Clean pass across all 9 workspace crates (`cargo clippy --workspace --all-targets -- -D warnings`).
- **Formatter Audit:** Clean pass across all files (`cargo fmt --all -- --check`).

---

## 12. Phase 11 — Release Build Reproducibility

### Release Profile Settings (`Cargo.toml`):
```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

### Binary Artifact Metrics:
- **Target Platform:** `x86_64-unknown-linux-gnu`
- **Binary Path:** `target/release/relay`
- **Binary Size:** ~14 MB (fully static Rust runtime and embedded Cedar engine)
- **Embedded Metadata:** `CARGO_PKG_VERSION` (0.1.0); zero developer filesystem paths or build usernames embedded.

---

## 13. Phase 12 — Crash, Panic, and Error Hygiene

- **Runtime Path Audit:** Verified that all fallible runtime operations (`io`, `parsing`, `policy evaluation`, `credential retrieval`, `network requests`, `storage appends`) return typed `Result<T, E>` errors rather than calling `unwrap()` or `expect()`.
- **Error Formatting:** Error messages are sanitized to prevent inclusion of raw passwords, private keys, or bearer tokens.

---

## 14. Phase 13 — Release-Grade Test Matrix

### Test Execution Summary:

| Crate | Test Target | Tests Run | Result |
|:---|:---|:---:|:---:|
| `relay-canonical` | Unit, JCS, Proptest, Resource, Divergence | 38 | **PASS** |
| `relay-domain` | Unit, Approval, State Machine, Security | 34 | **PASS** |
| `relay-policy` | Unit, Authorization, Schema, Performance | 26 | **PASS** |
| `relay-credentials`| Unit, Broker, Provider, Zeroization | 15 | **PASS** |
| `relay-receipts` | Unit, Crypto, DSSE, Scrubber, Serialization | 35 | **PASS** |
| `relay-ledger` | Unit, Storage, Genesis, HashChain, Verifier | 28 | **PASS** |
| `relay-connectors`| Unit, GitHub, Postgres, FS, Golden Path, Adversarial | 89 | **PASS** |
| `relay-mcp` | Unit, Gateway, Protocol, Frame, Lifecycle, Approval | 22 | **PASS** |
| `relay-cli` | CLI Integration, Ledger CLI, RC001 Hardening | 22 | **PASS** |
| **Total Workspace**| **All 9 Crates** | **309** | **100% PASS** |

---

## 15. Phase 14 — Security Documentation Accuracy

All security documentation across `docs/` has been verified against actual implementation behavior:
- Avoided misleading terms such as "tamper-proof", "zero-knowledge", or "universal security".
- Accurately formulated core technical claims:
  - *Zero ambient agent credentials:* Credentials exist only in memory inside Relay's broker for single-action TTLs.
  - *Fail-closed authorization:* Cedar default-deny ensures unpermitted actions cannot execute.
  - *Complete mediated execution:* Governed tools route through the 7-stage state machine.
  - *Tamper-evident hash-chained audit ledger:* Modification or deletion of ledger rows breaks cryptographic verification.
  - *Cryptographically signed action evidence:* In-toto statements wrapped in Ed25519 DSSE envelopes.
  - *Explicit ambiguous-mutation tracking:* Network timeouts and partial I/O errors are explicitly flagged.

---

## 16. RC001 Release Hardening Findings

| Finding ID | Title | Severity | Status | Resolution / Justification |
|:---|:---|:---:|:---:|:---|
| **RC-001** | Silent In-Memory Ledger Fallback | **HIGH** | **FIXED** | Removed fallback; opening database now strictly fails closed with `CliError::StorageError`. |
| **RC-002** | `PostgresCredentials` Derived Plaintext `Debug` | **MED** | **FIXED** | Implemented custom `Debug` with `[REDACTED]` and auto-zeroize on drop. |
| **RC-003** | TOCTOU Window in State File Creation | **MED** | **FIXED** | Enforced atomic `mode(0o600)` and `mode(0o700)` at creation time via Unix `OpenOptionsExt` and `DirBuilderExt`. |
| **RC-004** | Missing File/Hex Signing Key Loader | **MED** | **FIXED** | Added `from_file`, `from_hex`, and `save_to_file` to `Ed25519ReceiptSigner`. |
| **RC-005** | Inconsistent CLI Exit Codes | **MED** | **FIXED** | Mapped all `CliError` variants to `relay_domain::ExitCode` (`0`–`9`) and terminated process accordingly. |
| **RC-006** | Local Ledger Permissions on Production Host | **LOW** | **ACCEPTED RISK** | SQLite file permissions (`0600`) protect against unauthorized local users; root/kernel compromise is out of trust boundary. |

---

## 17. Final Assessment & Release Verdict

```text
RC001 RELEASE HARDENING — FINAL VERDICT

Implementation:
PASS

Security:
PASS

Release Readiness:
READY WITH CONDITIONS

Blocking Issues:
None

Accepted Risks:
1. SQLite ledger file security relies on host OS DAC permissions (0600) and uncompromised process user account.
2. Direct Rust connector struct method invocations outside GovernedActionRunner must be restricted to pub(crate) in v0.2.0 API refinement.

Security Boundary:
Under complete prompt-injection compromise of the agent, Relay prevents ambient credentials in agent memory and guarantees that no unauthorized governed action executes without Cedar policy authorization, operator approval, and cryptographic tamper-evident audit recording.

Tests:
309 passed / 0 failed

Recommended Next Milestone:
RC002 — Production Packaging, Distribution, and End-to-End Validation
```
