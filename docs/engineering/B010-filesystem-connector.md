# Milestone B010: Native Governed Filesystem Connector

**Status:** Completed & Verified  
**Milestone:** B010  
**Specification References:** [R003 Agent Authority Model](../research/R003-agent-authority-model.md), [R009 Trust Boundary](../research/R009-trust-boundary.md), [R010 JIT Credentials](../research/R010-jit-credentials.md), [R011 Action Receipts](../research/R011-action-receipts.md), [R015 Build Gate](../research/R015-build-gate.md), [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A006 Persistence & Storage](../architecture/A006-persistence-and-storage.md), [A008 Rust Dependency Architecture](../architecture/A008-rust-dependency-architecture.md), [A010 Build Specification](../architecture/A010-build-specification.md)  
**Implementation Crates:** `crates/relay-connectors`, `crates/relay-domain`, `crates/relay-canonical`, `crates/relay-policy`, `crates/relay-receipts`, `crates/relay-ledger`

---

## 1. Executive Summary

Milestone B010 establishes the **Native Governed Filesystem Connector** for Relay.

Filesystem access is one of the highest-risk capabilities granted to autonomous AI agents. Flawed filesystem implementations frequently lead to arbitrary file reads (e.g. `/etc/passwd`, private keys, environmental `.env` files), arbitrary file writes (e.g. code injection, cron overwrites, authorized_keys hijacking), path traversal (`../../`), symlink abuse, and Time-of-Check to Time-of-Use (TOCTOU) race conditions.

Milestone B010 implements an in-process, non-shell filesystem execution engine governed end-to-end by the Relay security architecture:

```text
MCP tools/call ("fs.read", "fs.write", "fs.delete", etc.)
      ↓
CanonicalAction (B003: Lexical normalization, PathBuf resolution, ResourceUri: file:///...)
      ↓
Cedar PEP (B004: Strict default-deny, exact Cedar action mapping, sensitivity forbidden rules)
      ↓
Native Filesystem Connector (B010: In-process governed execution within strict root jail)
      ↓
Physical Filesystem (Atomic writes via tmp+fsync+rename, bounded I/O, symlink rejection)
      ↓
Execution Observation (Bounded output materialization, duration, status)
      ↓
Action Receipt (B007: Cryptographically signed DSSE in-toto Statement v1.0)
      ↓
Evidence Ledger (B008: Append-only hash-chained SQLite persistence)
```

The connector guarantees that:
1. Every access is confined within a designated `root_dir` jail; all relative traversal, absolute path escape, virtual filesystem traversal (`/proc`, `/sys`, `/dev`), and symlink escapes are hard-rejected.
2. File modifications are atomic (writes go to `.tmp.<name>.<uuid_v7>` on the same filesystem, are synchronized with `fsync`, and atomically renamed onto the destination path).
3. Non-idempotent mutation failures or ambiguous outcomes (disk full, partial writes) are classified conservatively as `AmbiguousMutationOutcome` and never silently retried.
4. Every governed operation emits an Ed25519 DSSE in-toto receipt cryptographically bound to the canonical action hash and persisted in the immutable evidence ledger.

---

## 2. Complete Architecture Execution Path

```text
+----------------------------------------------------------------------------------------------------+
|                                B010 GOVERNED EXECUTION PIPELINE                                    |
|                                                                                                    |
|  [Agent / Client]                                                                                  |
|         │                                                                                          |
|         ▼ tools/call { "name": "relay.fs.read", "arguments": { "path": "workspace/report.txt" }}   |
|  [ActionCanonicalizer (B003)]                                                                      |
|         │  • Lexical path normalization (strips redundant slashes, resolves relative components)   |
|         │  • Formats canonical ResourceUri: file:///workspace/report.txt                            |
|         │  • Computes deterministic ActionHash (RFC 8785 JCS + SHA-256)                            |
|         ▼                                                                                          |
|  [CanonicalAction] ───► [Cedar PEP (B004)]                                                         |
|                               │                                                                    |
|                               ▼ Is Allowed?                                                        |
|                     ┌─────────┴─────────┐                                                          |
|                     │ NO                │ YES                                                      |
|                     ▼                   ▼                                                          |
|               DENY (fail closed)   [PolicyDecision { ALLOW/APPROVAL, ActionHash, PolicyDigest }]   |
|                                         │                                                          |
|                                         ▼                                                          |
|                                    [Human Approval Required?] ──► [Approval Verification]          |
|                                         │  • Validates approval signature & ActionHash binding     |
|                                         ▼                                                          |
|                                    [FilesystemConnector::execute_governed()]                       |
|                                         │                                                          |
|                                         ├─► 1. Verify ActionHash binding:                          |
|                                         │      action.action_hash == decision.action_hash          |
|                                         │      approval.action_hash == action.action_hash (if req) |
|                                         ├─► 2. Extract execution plan:                             |
|                                         │      Cross-validate path argument with canonical URI     |
|                                         │      Parse operation: read, write, append, delete, ...   |
|                                         ├─► 3. Jail & Boundary Validation:                         |
|                                         │      Check prohibited system prefixes (/proc, /sys, ...) |
|                                         │      Resolve canonical physical path                     |
|                                         │      Verify starts_with(root_dir)                        |
|                                         │      Reject symlinks (if follow_symlinks is false)       |
|                                         │      Reject non-regular special files (block, char, FIFO)|
|                                         ├─► 4. Execute Bound & Atomic I/O:                         |
|                                         │      Read: limited to max_read_bytes (10MB)              |
|                                         │      List: limited to max_dir_entries (1,000)            |
|                                         │      Write: write tmp + fsync + atomic rename            |
|                                         │      Append: open existing with .create(false) + fsync   |
|                                         │      Delete: regular file unlink                         |
|                                         │      RemoveDir: non-recursive directory remove           |
|                                         ▼                                                          |
|                                    [ActionReceiptBuilder (B007)]                                   |
|                                         │  • In-toto Statement v1.0 format                         |
|                                         │  • DSSE envelope signed via Ed25519                      |
|                                         │  • Captures exact ActionHash, timestamps, digests        |
|                                         │  • Captures AmbiguousMutationOutcome on partial failure  |
|                                         ▼                                                          |
|                                    [SqliteLedger::append() (B008)]                                 |
|                                         │  • Hash-chained storage with immutability triggers       |
|                                         ▼                                                          |
|                                    [ExecutionResult returned to caller]                            |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Precondition Decision Rationale: Ordinary Local Filesystem vs Credentials

### 3.1. Explicit Architectural Boundary

A critical design determination was made for Milestone B010:

> **Precondition Decision:** Ordinary local filesystem operations do **NOT** invoke the `CredentialBroker`. They operate under the host operating system's process authority, constrained strictly by Relay's root jail and Cedar policy.

### 3.2. Rationale
1. **Host Process Authority**: In a containerized or sandboxed deployment, the Relay daemon runs under a designated unprivileged OS user/group. Standard POSIX filesystem operations (`open`, `read`, `write`, `unlink`) require no secret exchange, bearer token, or username/password lease.
2. **Preventing Security Theater**: Introducing artificial dummy credentials or empty credential leases for local file I/O would degrade performance, introduce unnecessary code paths, and create misleading audit artifacts.
3. **Defense-in-Depth Model**: Filesystem containment in Relay is enforced through **structural containment** (lexical + physical root jailing) combined with **declarative Cedar authorization** (path pattern filtering, sensitive file blacklists like `.env` and `id_rsa`, and step-up approvals on destructive actions).
4. **Future Remote / Encrypted Extensibility**: In subsequent milestones where Relay introduces remote network shares (e.g. S3, SMB, WebDAV) or cryptographically sealed volumes requiring decryption keys, those specialized storage connectors will acquire JIT leases through `CredentialBroker` following the established B005/B009 pattern.

---

## 4. Root-Jail Containment Model & Path Security Boundary

The filesystem jail (`crates/relay-connectors/src/fs/jail.rs`) implements a defense-in-depth barrier against path escapes.

### 4.1. Prohibited System Paths
Any path starting with or resolving to known virtual or sensitive OS paths is rejected immediately before filesystem interaction:
- `/proc`, `/sys`, `/dev` (virtual filesystems and device nodes)
- `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` (system identity files)
- `/root`, `/var/run`, `/var/lock`

### 4.2. Dual Normalization & Jail Containment
Path resolution executes in two distinct phases:
1. **Lexical Normalization (`normalize_path`)**:
   - Strips leading `/` to make paths relative to `root_dir`.
   - Resolves `.` and `..` lexically without touching the disk.
   - Rejects any path attempting to traverse above the synthetic root.
2. **Physical Path Resolution (`resolve_and_verify_within_root`)**:
   - Resolves the absolute path: `root_dir.join(normalized)`.
   - If the target exists, calls `std::fs::canonicalize` on the target.
   - If the target does not exist (for write/create operations), calls `std::fs::canonicalize` on the target's nearest existing ancestor directory.
   - Verifies that the canonicalized path strictly starts with `canonical_root`.
   - Ensures no directory symlinks allow escaping outside the root directory.

### 4.3. Symlink Policy Enforcement
- **Default Policy (`follow_symlinks = false`)**: If any path component is a symlink, the operation is immediately aborted with `FsError::SymlinkDisallowed`.
- **Special Device Nodes**: If a target path resolves to a block device, character device, FIFO pipe, or socket, `FsError::SpecialFileNotAllowed` is returned.

---

## 5. Supported Filesystem Operations & Mutation Semantics

| Operation | Method | Cedar Action | Description | Mutation Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Read File** | `read_file` | `Relay::Action::"fs.read"` | Reads file content up to `max_read_bytes` (10MB). | Idempotent, Read-only |
| **List Directory** | `list_directory` | `Relay::Action::"fs.read"` | Lists directory entries up to `max_dir_entries` (1,000). | Idempotent, Read-only |
| **Stat Metadata** | `stat_metadata` | `Relay::Action::"fs.read"` | Queries file size, permissions, modification time, and file type. | Idempotent, Read-only |
| **Write File (Atomic)** | `write_file_atomic` | `Relay::Action::"fs.write"` | Writes content via temporary file, `fsync`, and atomic rename. | Fully Atomic (`All-or-Nothing`) |
| **Append File** | `append_file` | `Relay::Action::"fs.write"` | Appends content to an *existing* file with `fsync`. | Non-idempotent, existing file required |
| **Create Directory** | `create_directory` | `Relay::Action::"fs.write"` | Creates a directory (including parents) within root. | Idempotent mutation |
| **Delete File** | `delete_file` | `Relay::Action::"fs.delete"` | Unlinks a regular file or symlink. Step-up approval required by default. | Idempotent mutation |
| **Remove Directory** | `remove_directory` | `Relay::Action::"fs.delete"` | Removes an *empty* directory. Rejects non-empty directories. | Strict Non-Recursive |

### 5.1. Atomic Write Mechanics
To prevent partial file corruption, truncation races, and data loss during concurrent reads or sudden power failure:
1. Generate unique temporary filename in the **same parent directory**:
   ```text
   .tmp.<original_stem>.<uuid_v7>
   ```
2. Open temporary file with `std::fs::OpenOptions::new().write(true).create_new(true)`.
3. Stream contents up to `max_write_bytes`.
4. Call `temp_file.sync_all()` (`fsync`) ensuring data and metadata are flushed to physical non-volatile storage.
5. Execute atomic rename (`std::fs::rename`) replacing the destination path atomically.

### 5.2. Append Guardrails
To prevent agents from bypassing file creation controls or corrupting arbitrary paths via appends:
- `append_file` explicitly configures `.create(false)`.
- The target file must already exist; appending to a non-existent path returns `FsError::NotFound`.
- After writing, `file.sync_all()` is executed to ensure durability.

### 5.3. Rejection of Recursive Deletion
Relay explicitly forbids recursive directory deletion (`rm -rf` equivalents) at the connector level. `remove_directory` calls `std::fs::remove_dir`, which fails if the directory contains any child files or subdirectories. This bounds blast radius and prevents accidental erasure of entire project trees.

---

## 6. TOCTOU Mitigations & Race Condition Defenses

Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities occur when filesystem state changes between the authorization check and physical I/O. Relay implements three layers of defense:

1. **Ancestor Directory Canonicalization**: For non-existent target files, canonicalization resolves the parent directory rather than relying on unverified string path concatenations.
2. **Same-Directory Temporary File Placement**: Temporary write files are created strictly within the target's verified parent directory. This guarantees that `rename()` is an atomic intra-filesystem inode move rather than a cross-device copy-and-delete.
3. **Bounded Reads & Memory Protection**: Read operations inspect metadata length before reading, but also employ `take(max_read_bytes)` on the read stream, preventing memory exhaustion from dynamic virtual files or race modifications.

---

## 7. Ambiguous Mutation & Partial Failure Handling (Preflight Audited & Corrected)

Filesystem mutations require strict discernment between known failures and truly ambiguous mutations:

### 7.1 Known Failures vs Ambiguous Mutations
- **Atomic File Writes (`write_file_atomic`)**: Writes follow `temporary file -> write -> fsync -> atomic rename`. If `ENOSPC`, I/O failure, or rename failure occurs, the temporary file is unlinked and the destination path remains completely untouched. These are **known failures** (`ExecutionObservationStatus::TargetError`, `retry_classification: NonRetryableFatal`), NOT ambiguous mutations.
- **Directory Deletion (`remove_directory`)**: If `remove_directory` fails because the directory is non-empty (`DirectoryNotEmpty`) or permissions are denied, the directory and its child files remain intact on disk. This is a **known failure** (`TargetError`, `NonRetryableFatal`).
- **File Deletion (`delete_file`)**: If `remove_file` fails due to permissions or file locks, the target was not deleted. This is a **known failure** (`TargetError`, `NonRetryableFatal`).
- **Directory Creation (`create_directory`)**: Directory creation uses `create_dir_all` which is idempotent.
- **True Ambiguous Mutation (`append_file`)**: Unlike atomic writes, `append_file` appends directly to an existing file. A mid-stream failure (such as disk exhaustion `ENOSPC` during `write_all` or interrupted sync) can leave the file with partial content. In this scenario, Relay cannot know whether the mutation occurred completely, partially, or was rolled back by the OS. This is strictly classified as:
  ```rust
  FsError::AmbiguousMutationOutcome {
      operation: "append_file".to_string(),
      path: path.display().to_string(),
      reason: format!("Partial append failure: {e}"),
  }
  ```
  and recorded in the `ActionReceipt` with:
  - `status: ExecutionObservationStatus::AmbiguousMutation`
  - `retry_classification: "AmbiguousRequiresVerification"`
- Non-idempotent mutations are **never automatically retried**.

---

## 8. Security Invariants Verification (A004)

| Invariant | Description | B010 Filesystem Implementation Mechanism |
| :--- | :--- | :--- |
| **SI-001** | Fail Closed Default Deny | If Cedar returns anything other than `ALLOW` (or valid `ApprovalRequired`), no filesystem I/O is performed. |
| **SI-002** | Complete Mediation | All filesystem calls flow through `execute_governed`. Direct unverified calls to `NativeConnector::execute` fail closed with `PolicyDenial`. |
| **SI-006** | Cryptographic ActionHash Binding | The connector strictly validates `canonical_action.action_hash == decision.action_hash` before path resolution or dispatch. |
| **SI-007** | Strict Canonicalization Authority | Path arguments are cross-validated against the canonical `ResourceUri`. Discrepancies abort execution immediately. |
| **SI-008** | Ephemeral JIT Credential Minimization | Ordinary filesystem operations operate under host OS credentials without ambient secret leakage. |
| **SI-009** | Cryptographic Receipt Production | Every execution emits a DSSE in-toto Statement v1.0 receipt signed with Ed25519, recording input/output digests. |
| **SI-010** | Immutable Hash-Chained Ledger Persistence | Every receipt is appended to the SQLite ledger (`ledger.db`) extending the cryptographic hash chain. |
| **SI-013** | Conservative Ambiguous Mutation Handling | Disk full or partial write failures emit `AmbiguousMutationOutcome` and are marked requiring human verification. |
| **SI-014** | Root-Jail Containment | Paths are constrained to `root_dir`. Traversal, symlink escapes, and prohibited OS paths are rejected. |

---

## 9. Comprehensive Adversarial Test Matrix

All 25 adversarial test vectors specified for the Filesystem boundary were implemented and verified in `crates/relay-connectors/tests/fs_security_tests.rs`:

| ID | Attack Vector | Result | Mechanism |
| :--- | :--- | :--- | :--- |
| **01** | Relative path traversal (`../../etc/passwd`) | **PREVENTS** | Lexical & physical canonicalization catches escape; returns `PathTraversal`. |
| **02** | Absolute path escape (`/etc/shadow`) | **PREVENTS** | Prohibited prefix check rejects system paths (`ProhibitedSystemPath`). |
| **03** | Absolute path escape outside root (`/var/log/syslog`) | **PREVENTS** | Verified canonical path does not start with `root_dir` (`PathTraversal`). |
| **04** | Symlink traversal out of root jail | **PREVENTS** | `follow_symlinks = false` rejects symlink resolution (`SymlinkDisallowed`). |
| **05** | Symlink chain out of root jail | **PREVENTS** | Intermediate symlink components detected and rejected. |
| **06** | Prohibited system virtual path (`/proc/cpuinfo`) | **PREVENTS** | Caught by `PROHIBITED_PREFIXES` check before filesystem access. |
| **07** | Prohibited system virtual path (`/sys/kernel`) | **PREVENTS** | Caught by `PROHIBITED_PREFIXES` check. |
| **08** | Prohibited device node access (`/dev/urandom`) | **PREVENTS** | Caught by `PROHIBITED_PREFIXES` check. |
| **09** | Special device file inside jail (FIFO / pipe) | **PREVENTS** | `stat` check identifies non-regular file; returns `SpecialFileNotAllowed`. |
| **10** | Oversized file read attack (> 10MB) | **PREVENTS** | Metadata check & bounded stream reader reject with `FileTooLarge`. |
| **11** | Oversized file write attack (> 10MB) | **PREVENTS** | Payload size check rejects before writing to disk (`FileTooLarge`). |
| **12** | Directory entry flood (> 1,000 entries) | **PREVENTS** | Directory scanner aborts with `DirectoryEntryLimitExceeded`. |
| **13** | ActionHash substitution | **PREVENTS** | Connector validates `action.action_hash == decision.action_hash`. |
| **14** | Mismatched path in canonical resource vs arguments | **PREVENTS** | `extract_execution_plan` cross-validates canonical URI with path argument. |
| **15** | Step-up approval bypass on file deletion | **PREVENTS** | Cedar policy flags delete as `ApprovalRequired`; unapproved call fails closed. |
| **16** | Unapproved action hash bound to approval | **PREVENTS** | Connector verifies `approval.action_hash == action.action_hash`. |
| **17** | Expired approval token | **PREVENTS** | `approval.is_valid(now)` checks expiration timestamp. |
| **18** | Forbidden file access via Cedar policy (`.env`) | **PREVENTS** | Cedar PEP returns `DENY`; connector aborts before I/O. |
| **19** | Non-existent file read | **PREVENTS** | Handled cleanly; returns `FsError::NotFound`. |
| **20** | Non-empty directory deletion | **PREVENTS** | Strict non-recursive deletion; returns `FsError::NotEmpty`. |
| **21** | Atomic write preserves destination on failure | **VERIFIES** | Existing destination file remains untouched if temporary write fails. |
| **22** | Append fails on non-existent file | **PREVENTS** | Configured `.create(false)`; returns `FsError::NotFound`. |
| **23** | Special character path handling (spaces, quotes) | **VERIFIES** | Clean path parsing handles complex UTF-8 filenames correctly. |
| **24** | Ambiguous mutation produces signed receipt | **VERIFIES** | When operation fails on target, an `ActionReceipt` is still produced and signed. |
| **25** | Unmatched tool action fail closed | **PREVENTS** | Unsupported operations fail closed with `PolicyDenial`. |

---

## 10. Performance Characterization

Microbenchmarks and pipeline performance were evaluated in `crates/relay-connectors/tests/fs_performance_tests.rs`:

| Operation / Benchmark | Measured Latency | SLA Target | Result |
| :--- | :--- | :--- | :--- |
| **Jail Path Resolution & Canonicalization** | **~6.85 µs** | < 200 µs | **PASS** (30x faster than target) |
| **Bounded Read (64 KB)** | **~0.24 ms** | < 5.0 ms | **PASS** |
| **Atomic Write (64 KB + fsync + rename)** | **~2.30 ms** | < 10.0 ms | **PASS** (dominated by hardware fsync) |
| **Directory Listing (100 entries)** | **~0.45 ms** | < 5.0 ms | **PASS** |
| **Full Governed Read Pipeline** | **~2.80 ms** | < 10.0 ms | **PASS** |

*(Pipeline benchmark includes: Canonicalization + Cedar PEP evaluation + Filesystem read + DSSE Ed25519 signing + ActionReceipt construction).*

---

## 11. Milestone Handoff: B011 Interactive Approval Provider

With Milestone B010 complete, Relay has implemented all governed execution connectors planned for the MVP (GitHub, PostgreSQL, Filesystem).

Milestone B011 will implement the **Interactive Approval Provider / Headless Approval Gate**:
1. **Interactive Human Approval Channel**: Terminal UI / headless CLI prompts allowing human operators to inspect pending sensitive actions (e.g. file deletion, table drop, repository push) and grant or deny approval cryptographically.
2. **Approval Signature Generation**: Producing valid, signed `Approval` domain objects bound to the exact `action_hash`.
3. **Timeout & Expiration Management**: Handling TTL expiry of pending approvals cleanly.
4. **Integration with Governed Connectors**: Demonstrating end-to-end flow where a mutating connector requests approval, waits on the interactive provider, and completes governed execution with audit receipts.
