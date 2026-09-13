# A006: Persistence & Storage Architecture Specification

**Document Version:** 1.0.0  
**Status:** Canonical Design  
**Author:** Relay Core Architecture Team  
**Scope:** Relay MVP Storage Subsystem, Cryptographic Ledger, Secret Residency, Durability & Recovery Model  
**Related Documents:**
- [`A001-system-architecture.md`](file:///home/sumeet/relay/docs/architecture/A001-system-architecture.md)
- [`A002-domain-model.md`](file:///home/sumeet/relay/docs/architecture/A002-domain-model.md)
- [`A003-interfaces-and-contracts.md`](file:///home/sumeet/relay/docs/architecture/A003-interfaces-and-contracts.md)
- [`R014-mvp-definition.md`](file:///home/sumeet/relay/docs/research/R014-mvp-definition.md)

---

## 1. Executive Summary & Architectural Scope

The Relay persistence layer is designed to solve a foundational problem in governed agent systems: **how to maintain an immutable, tamper-evident audit ledger and secure operational state without compromising latency, leaking credentials, or contaminating domain logic with database-specific abstractions.**

Relay MVP adopts an architectural model where:
1. **The domain model remains strictly decoupled from SQLite and filesystem primitives.** All domain entities (`ActionReceipt`, `LedgerEntry`, `Session`, `Approval`) are pure Rust data types agnostic of database tables, SQL syntax, or storage engines.
2. **Persistence is partitioned into three strict residency tiers:**
   - **Volatile Secure Memory (`zeroize` / `mlock`):** Target API secrets, intermediate session keys, and in-flight credential leases.
   - **OS Keyring (`keyring-rs` / Secret Service API / macOS Keychain):** Node-level asymmetric Ed25519 identity and signing private keys.
   - **Relational Append-Only Ledger (`SQLite 3.45+` with Write-Ahead Logging):** Cryptographic hash chain entries, canonical DSSE envelopes, policy evaluation metadata, and execution telemetry.
3. **The cryptographic ledger is mathematically tamper-evident.** Each ledger block binds the sequential sequence number, the previous ledger entry's hash, and the JCS canonical byte payload of the DSSE envelope containing the signed action receipt.
4. **Concurrency is modeled around single-writer message queues.** High-throughput async Tokio worker tasks submit persistence commands via a bounded `mpsc` channel to a dedicated background OS thread holding the single SQLite writer connection, eliminating write contention and lock thrashing.

```
+-----------------------------------------------------------------------------------+
|                               RELAY RUNTIME DOMAIN                                 |
|                                                                                   |
|   +-------------------+     +--------------------+     +----------------------+   |
|   | ActionReceipt     |     | LedgerEntry        |     | ApprovalRequest      |   |
|   | (in-toto DSSE)    |     | (Merkle/Chain Node)|     | (State Machine)      |   |
|   +---------+---------+     +---------+----------+     +----------+-----------+   |
+-------------|-------------------------|---------------------------|---------------+
              |                         |                           |
              v                         v                           v
+-----------------------------------------------------------------------------------+
|                       RELAY PERSISTENCE ADAPTER INTERFACE                         |
|                     (relay_core::ports::storage::LedgerStore)                     |
+---------------------------------------+-------------------------------------------+
                                        |
        +-------------------------------+-------------------------------+
        |                               |                               |
        v                               v                               v
+-----------------------+   +-----------------------+   +-----------------------+
|  VOLATILE MEMORY TIER |   |   OS KEYRING TIER     |   |    SQLITE WAL TIER    |
| - Target API Tokens   |   | - Ed25519 Node Secret |   | - receipts            |
| - In-flight Leases    |   | - Fallback AES Master |   | - ledger_entries      |
| - zeroize / mlock     |   | - OS-enforced ACLs    |   | - policy_snapshots    |
| - NEVER written to disk|  | - No custom vault     |   | - schema_migrations   |
+-----------------------+   +-----------------------+   +-----------------------+
```

---

## 2. State Taxonomy: Domain, Ephemeral, Derived & Prohibited

To prevent state leakage and lifecycle bugs, all data manipulated by Relay is classified into one of four distinct categories, dictating its persistence medium and lifetime.

```
+----------------------------------------------------------------------------------------+
|                                    STATE TAXONOMY                                      |
+--------------------+---------------------+---------------------+-----------------------+
| PERSISTED STATE    | EPHEMERAL STATE     | DERIVED STATE       | PROHIBITED STATE      |
+--------------------+---------------------+---------------------+-----------------------+
| - Action Receipts  | - Target API Tokens | - Merkle Root Hash  | - Raw API Secrets     |
| - Hash Chain Nodes | - In-flight Sockets | - Sequence Indices  | - Unmasked Tokens     |
| - Approvals        | - Active Leases     | - Verification Logs | - Plaintext Envs      |
| - Policy Hashes    | - Stdio Process FDs | - Ledger Head Hash  | - Memory Heap Dumps   |
| - Node Public Keys | - Nonces & Ephemera | - Policy AST Cache  | - Decrypted Vaults    |
+--------------------+---------------------+---------------------+-----------------------+
```

### 2.1. Persisted Domain State
State that must survive complete process restarts, host crashes, and operating system reboots. This state constitutes the permanent historical record:
1. **Ledger Entries (`ledger_entries` table):** Sequenced cryptographic nodes containing sequence index, UTC timestamp, parent hash, payload hash, and cumulative chain hash.
2. **DSSE Envelopes (`receipts` table):** Canonical in-toto Action Receipts containing tool namespaces, tool names, sanitized arguments, Cedar policy decisions, execution statuses, and Ed25519 cryptographic signatures.
3. **Policy Snapshots (`policy_snapshots` table):** Cryptographic SHA-256 digests and version tags of the active Cedar policy bundle utilized during action evaluation.
4. **Approval Records (`approvals` table):** Nonce-bound human approval decisions, approver identities, channel IDs (e.g., CLI, Slack, Webhook), and approval timestamps.
5. **Node Identity Public Keys (`node_identity` table):** Node UUID, public key material (hex/base64 encoded), and registration metadata.

### 2.2. Ephemeral State
State that exists strictly within process execution context and is safely discarded on shutdown or session termination:
1. **Active MCP Stdio/SSE Connections:** Subprocess standard I/O pipes, child process PIDs, and active SSE HTTP stream contexts.
2. **In-Flight Credential Leases:** Active short-lived leases undergoing active tool dispatch.
3. **Pending Inter-Task Synchronization Primitives:** `tokio::sync::oneshot` channels, `Notify` handles, and in-flight mutex locks.
4. **Policy Engine In-Memory Evaluator:** Pre-compiled Cedar ASTs and policy evaluation graphs cached in memory.

### 2.3. Derived State
State that is deterministically computed from persisted state and can be recomputed on-demand without loss of integrity:
1. **Current Ledger Head Hash:** Computed by reading the latest sequenced entry from `ledger_entries` or walking the chain from Genesis.
2. **Chain Integrity Verification Status:** Computed by streaming through `ledger_entries` in sequential order and evaluating $H_n = \text{SHA-256}(S_n \mathbin{\Vert} H_{n-1} \mathbin{\Vert} D_n)$.
3. **Audit Query Aggregations:** Summary statistics, tool call frequency tables, policy denial rates, and latency distributions.

### 2.4. Prohibited State (State that Must NEVER Be Persisted)
Under no circumstances may the following data types touch SQLite, disk files, unencrypted swap, or logging subsystems:
1. **Target API Credentials:** AWS Access Keys, GitHub Personal Access Tokens, GCP OAuth Tokens, Bearer Tokens, Database Passwords.
2. **Ephemeral Decryption Keys:** Symmetric keys used during in-flight communication.
3. **Unsanitized Execution Payloads:** Tool execution stdout/stderr streams containing raw bearer tokens, password arguments, or sensitive environment variables.
4. **Private Identity Keys in SQLite:** The node's Ed25519 private signing key must **never** be stored in SQLite database tables or WAL files.

---

## 3. Storage Tier Partitioning & Boundaries

Relay enforces physical and logical isolation between storage tiers.

```
+-----------------------------------------------------------------------------------+
|                               RELAY PROCESS MEMORY                                 |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | [SECURE MEMORY HEAP: zeroize / mlock]                                       |  |
|  | - SecretBuffer { ptr, len, capacity }                                       |  |
|  | - Auto-zeroized on Drop; protected against core dumps & memory paging         |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | [STANDARD APPLICATION HEAP]                                                 |  |
|  | - Tokio Task Contexts, Domain Entities, Cedar AST Cache                     |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
            |                                                   |
            | IPC / System Calls                                | Thread MPSC Channel
            v                                                   v
+---------------------------------------+   +---------------------------------------+
|            OS KEYRING TIER            |   |          LOCAL FILESYSTEM TIER        |
|                                       |   |                                       |
| - macOS: Security Keychain Services   |   | - ~/.relay/data/ledger.db             |
| - Linux: Secret Service API / D-Bus   |   | - ~/.relay/data/ledger.db-wal         |
| - Windows: Credential Manager (DPAPI) |   | - ~/.relay/data/ledger.db-shm         |
| - Fallback: Argon2id Encrypted Key    |   | - Permissions: 0700 dir, 0600 files   |
+---------------------------------------+   +---------------------------------------+
```

### 3.1. OS Keyring Tier (Secret Storage Rules)
- **Engine:** Managed via the standard Rust `keyring` crate utilizing native OS security daemons.
- **Payload:** Node Identity Private Key (`ed25519_sk`).
- **Service Name:** `io.relay.gateway`
- **Account Key:** `node-identity:<NODE_UUID>`
- **Access Policy:**
  - Secrets are retrieved only once at daemon startup or signing worker initialization.
  - Secret bytes are immediately moved into a `secrecy::Secret<[u8; 32]>` or `zeroize::Zeroizing<Vec<u8>>` wrapper.
  - No custom password databases, plaintext configuration files, or proprietary vault daemons are introduced for MVP.

#### Headless / CI Fallback Behavior
When running in headless Linux environments without D-Bus or X11 Secret Service (`libsecret-1.so` unavailable), Relay falls back to a deterministic, secure file-based key vault:
1. File location: `~/.relay/keys/node.key` (Strict UNIX mode `0600`, directory mode `0700`).
2. Cipher: `AES-256-GCM` with a 96-bit random nonce.
3. Key Derivation: Master key derived from the user-provided `RELAY_MASTER_KEY` environment variable or standard input using **Argon2id** ($m=64\,\text{MiB}, t=3, p=4$).
4. If no master key is provided in a headless environment, Relay halts with exit code `EX_NOPERM (77)` and outputs a structured error refusing to persist plaintext keys.

### 3.2. Local SQLite WAL Tier
- **Database Path:** `~/.relay/data/ledger.db`
- **Access Mode:** Dedicated SQLite single-writer worker thread + pooled multi-reader connections.
- **Locking Protocol:** WAL (Write-Ahead Logging) mode with `PRAGMA busy_timeout = 5000;`.
- **Operating System Permissions:** Directory `0700` (`rwx------`), Database and WAL files `0600` (`rw-------`). On startup, Relay verifies POSIX permissions and aborts if file ownership or modes are permissive.

---

## 4. SQLite Schema & Relational Design

The relational schema is optimized for append-only audit workloads, immutable receipt storage, and zero-overhead integrity verification.

```
+---------------------------------------------------------------------------------------------+
|                                    SQLITE LEDGER SCHEMA                                     |
+-----------------------------------+                     +-----------------------------------+
|          ledger_entries           |                     |             receipts              |
+-----------------------------------+                     +-----------------------------------+
| PK  sequence_number  INTEGER      | 1                 1 | PK  receipt_id     TEXT (UUIDv7)  |
|     receipt_id       TEXT (FK)    +---------------------+     sequence_number INTEGER (FK)  |
|     timestamp_utc    TEXT (ISO)   |                     |     timestamp_utc   TEXT (ISO)    |
|     parent_hash      TEXT (HEX)   |                     |     tool_namespace  TEXT          |
|     payload_hash     TEXT (HEX)   |                     |     tool_name       TEXT          |
|     entry_hash       TEXT (HEX)   |                     |     decision        TEXT          |
|                                   |                     |     status          TEXT          |
| UK  entry_hash                    |                     |     dsse_envelope   BLOB (JSON)   |
| UK  receipt_id                    |                     |     raw_payload_len INTEGER       |
+-----------------------------------+                     +-----------------------------------+
                 | 1                                                        | 1
                 |                                                          |
                 | 1                                                        | 0..1
+-----------------------------------+                     +-----------------------------------+
|         policy_snapshots          |                     |             approvals             |
+-----------------------------------+                     +-----------------------------------+
| PK  policy_id        TEXT (UUID)  |                     | PK  approval_id    TEXT (UUIDv7)  |
|     policy_hash      TEXT (HEX)   |                     |     receipt_id     TEXT (FK)      |
|     cedar_bundle     TEXT         |                     |     approver_id    TEXT           |
|     created_at_utc   TEXT (ISO)   |                     |     approval_type  TEXT           |
+-----------------------------------+                     |     decision       TEXT           |
                                                          |     decided_at_utc TEXT (ISO)     |
                                                          +-----------------------------------+
```

### 4.1. Complete DDL Specification

```sql
-- Relay Storage Initialization DDL (Version 001)
-- Requires SQLite 3.45+ with JSON and WAL support.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA auto_vacuum = INCREMENTAL;

-- -----------------------------------------------------------------------------
-- 1. Schema Migrations Ledger
-- Tracks applied database migrations and schema versions.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version         INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    applied_at_utc  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    checksum_sha256 TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- 2. Node Identity Table
-- Stores the local gateway node metadata and public signing key.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS node_identity (
    node_id         TEXT PRIMARY KEY,
    public_key_hex  TEXT NOT NULL,
    key_algorithm   TEXT NOT NULL DEFAULT 'ed25519',
    initialized_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);

-- -----------------------------------------------------------------------------
-- 3. Policy Snapshots Table
-- Records immutable Cedar policy bundles evaluated during agent operations.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_snapshots (
    policy_hash     TEXT PRIMARY KEY,
    cedar_bundle    TEXT NOT NULL,
    created_at_utc  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- -----------------------------------------------------------------------------
-- 4. Cryptographic Ledger Entries Table
-- Strict append-only hash chain linking every governed action sequentially.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ledger_entries (
    sequence_number INTEGER PRIMARY KEY,
    receipt_id      TEXT NOT NULL UNIQUE,
    timestamp_utc   TEXT NOT NULL,
    parent_hash     TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    entry_hash      TEXT NOT NULL UNIQUE,
    
    -- Invariant: parent_hash must match preceding entry's entry_hash (enforced by trigger/engine)
    CONSTRAINT check_hashes_hex CHECK (
        length(parent_hash) = 64 AND 
        length(payload_hash) = 64 AND 
        length(entry_hash) = 64
    )
);

-- -----------------------------------------------------------------------------
-- 5. Action Receipts Table
-- Stores canonical in-toto DSSE envelopes and queryable metadata.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id          TEXT PRIMARY KEY,
    sequence_number     INTEGER NOT NULL UNIQUE,
    timestamp_utc       TEXT NOT NULL,
    tool_namespace      TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    decision            TEXT NOT NULL CHECK(decision IN ('Permit', 'Deny', 'PermitWithApproval')),
    status              TEXT NOT NULL CHECK(status IN ('Success', 'Failure', 'Denied', 'TimedOut', 'Aborted')),
    policy_hash         TEXT NOT NULL,
    dsse_envelope       BLOB NOT NULL,
    raw_payload_len     INTEGER NOT NULL,
    
    FOREIGN KEY (sequence_number) REFERENCES ledger_entries(sequence_number) ON DELETE RESTRICT,
    FOREIGN KEY (receipt_id) REFERENCES ledger_entries(receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (policy_hash) REFERENCES policy_snapshots(policy_hash) ON DELETE RESTRICT
);

-- -----------------------------------------------------------------------------
-- 6. Approvals Table
-- Tracks out-of-band and just-in-time human operator authorization grants.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approvals (
    approval_id         TEXT PRIMARY KEY,
    receipt_id          TEXT NOT NULL,
    nonce               TEXT NOT NULL UNIQUE,
    approver_id         TEXT NOT NULL,
    channel             TEXT NOT NULL CHECK(channel IN ('CLI', 'Slack', 'Webhook', 'Console')),
    decision            TEXT NOT NULL CHECK(decision IN ('Approved', 'Rejected', 'Expired')),
    decided_at_utc      TEXT NOT NULL,
    metadata_json       TEXT NOT NULL DEFAULT '{}',
    
    FOREIGN KEY (receipt_id) REFERENCES receipts(receipt_id) ON DELETE RESTRICT
);

-- -----------------------------------------------------------------------------
-- Indexes for Sub-Millisecond Verification and Query Performance
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger_entries(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_receipts_tool ON receipts(tool_namespace, tool_name);
CREATE INDEX IF NOT EXISTS idx_receipts_decision ON receipts(decision, status);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_approvals_receipt ON approvals(receipt_id);
```

### 4.2. Immutability Triggers (Defense-in-Depth)

To prevent accidental modification or deletion by buggy application code or unauthorized direct SQLite connections, Relay installs database-level triggers that reject `UPDATE` and `DELETE` statements on the ledger and receipt tables.

```sql
-- Prevent updates to ledger_entries
CREATE TRIGGER IF NOT EXISTS prevent_ledger_update
BEFORE UPDATE ON ledger_entries
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: ledger_entries is strictly append-only');
END;

-- Prevent deletes from ledger_entries
CREATE TRIGGER IF NOT EXISTS prevent_ledger_delete
BEFORE DELETE ON ledger_entries
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: ledger_entries rows cannot be deleted');
END;

-- Prevent updates to receipts
CREATE TRIGGER IF NOT EXISTS prevent_receipts_update
BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: receipts are cryptographically immutable');
END;

-- Prevent deletes from receipts
CREATE TRIGGER IF NOT EXISTS prevent_receipts_delete
BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: receipts cannot be deleted');
END;
```

---

## 5. Ledger Architecture & Cryptographic Hash Chain

The Relay cryptographic ledger guarantees that past audit records cannot be altered, reordered, inserted, or truncated without causing an immediate, detectable failure during chain verification.

```
                                      LEDGER CHAINING MECHANISM
                                      
  +---------------------------------+              +---------------------------------+
  |        LEDGER BLOCK n-1         |              |         LEDGER BLOCK n          |
  +---------------------------------+              +---------------------------------+
  | Sequence: n-1                   |              | Sequence: n                     |
  | Timestamp: 2026-03-31T12:00:00Z |              | Timestamp: 2026-03-31T12:00:01Z |
  | ParentHash: H_{n-2}             |              | ParentHash: H_{n-1} <-----------+---+ (Binds to
  | PayloadHash: SHA256(DSSE_{n-1}) |              | PayloadHash: SHA256(DSSE_n)     |   |  previous block)
  | EntryHash (H_{n-1})             +--------------+-> EntryHash (H_n)               |   |
  +---------------------------------+              +----------------+----------------+   |
                                                                    |                    |
                                 +----------------------------------+                    |
                                 |                                                       |
                                 v                                                       |
  +-----------------------------------------------------------------------------------+  |
  | MATHEMATICAL FORMULATION:                                                         |  |
  |                                                                                   |  |
  | H_n = SHA-256(                                                                    |  |
  |     BE_U64(Sequence_n) ||                                                         |  |
  |     HexDecode(ParentHash_{n-1}) ||                                                |  |
  |     HexDecode(PayloadHash_n)                                                      |  |
  | )                                                                                 |  |
  +-----------------------------------------------------------------------------------+--+
```

### 5.1. Exact Mathematical Chaining Rule

For any given ledger entry $n \ge 1$:

1. **Payload Hash Formulation:**
   $$\text{PayloadHash}_n = \text{SHA-256}(\text{CanonicalDSSEBytes}_n)$$
   where $\text{CanonicalDSSEBytes}_n$ represents the RFC 8785 JSON Canonicalization Scheme (JCS) representation of the in-toto DSSE Envelope containing the signed Action Receipt.

2. **Ledger Node Hash Formulation:**
   $$\text{EntryHash}_n = \text{SHA-256}\Big(\text{BE\_U64}(n) \mathbin{\Vert} \text{Bytes}(\text{ParentHash}_{n-1}) \mathbin{\Vert} \text{Bytes}(\text{PayloadHash}_n)\Big)$$
   - $\text{BE\_U64}(n)$: 8-byte big-endian representation of the sequence number $n$.
   - $\text{Bytes}(\text{ParentHash}_{n-1})$: 32 raw bytes derived from the 64-character lowercase hex string of entry $n-1$.
   - $\text{Bytes}(\text{PayloadHash}_n)$: 32 raw bytes of the SHA-256 digest of the DSSE envelope.

### 5.2. Genesis Block Definition

The Genesis Block represents sequence $n = 0$ and initializes the cryptographic ledger upon first boot:

$$\text{GenesisSequence} = 0$$
$$\text{GenesisParentHash} = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$
$$\text{GenesisPayload} = \text{JCS}\big(\{\text{"system"}: \text{"RELAY_GATEWAY_GENESIS"}, \text{"node_id"}: \text{NODE\_UUID}, \text{"version"}: \text{"1.0.0"}\}\big)$$
$$\text{GenesisPayloadHash} = \text{SHA-256}(\text{GenesisPayload})$$
$$\text{GenesisEntryHash} = \text{SHA-256}\Big(\text{BE\_U64}(0) \mathbin{\Vert} \text{Bytes}(0^{32}) \mathbin{\Vert} \text{Bytes}(\text{GenesisPayloadHash})\Big)$$

### 5.3. Append Atomicity & Concurrency Model

Relay ensures atomic, serialized ledger appends through an asymmetric concurrency architecture:
- **Write Path:** All Tokio worker tasks generate domain `ActionReceipt`s and submit an atomic `AppendReceiptCommand` through a bounded channel (`tokio::sync::mpsc::channel(1024)`) to the **Storage Engine Actor**.
- **Storage Engine Actor:** Runs on a dedicated OS thread pinned to a single SQLite connection. It performs the following steps inside a single SQLite transaction (`BEGIN IMMEDIATE`):
  1. Reads the latest sequence number $n-1$ and latest $\text{EntryHash}_{n-1}$.
  2. Increments sequence to $n$.
  3. Computes $\text{PayloadHash}_n$ and $\text{EntryHash}_n$.
  4. Inserts row into `ledger_entries`.
  5. Inserts corresponding row and DSSE envelope into `receipts`.
  6. Executes `COMMIT;`.
  7. Sends back the persisted `LedgerEntry` via `oneshot::Sender`.

```
+------------------+         +--------------------+         +-----------------------+
|  Tokio Worker 1  |         |   Tokio Worker 2   |         |    Tokio Worker N     |
+--------+---------+         +---------+----------+         +-----------+-----------+
         |                             |                                |
         | AppendReceiptCommand        | AppendReceiptCommand           | AppendReceiptCommand
         +--------------------+        |        +-----------------------+
                              |        |        |
                              v        v        v
                   +---------------------------------------+
                   |  mpsc::channel(1024) [Write Queue]   |
                   +-------------------+-------------------+
                                       |
                                       v
                   +---------------------------------------+
                   |     Storage Engine Actor Thread       |
                   |   (Dedicated OS Thread / Sync Rusqlite)|
                   |                                       |
                   |   1. BEGIN IMMEDIATE;                 |
                   |   2. Read Head (seq n-1, Hash n-1)    |
                   |   3. Compute Hash_n                   |
                   |   4. INSERT INTO ledger_entries       |
                   |   5. INSERT INTO receipts             |
                   |   6. COMMIT;                          |
                   +-------------------+-------------------+
                                       |
                                       v
                   +---------------------------------------+
                   |       Disk / SQLite WAL Files         |
                   +---------------------------------------+
```

---

## 6. Durability Model & I/O Engine

The storage engine is tuned for the Pareto frontier of sub-millisecond execution latency and zero-data-loss durability.

```
+------------------------------------------------------------------------------------+
|                             RELAY DURABILITY PROFILES                              |
+----------------------+--------------------+--------------------+-------------------+
| PARAMETER            | BALANCED (Default) | HIGH-ASSURANCE     | HIGH-THROUGHPUT   |
+----------------------+--------------------+--------------------+-------------------+
| journal_mode         | WAL                | WAL                | WAL               |
| synchronous          | NORMAL             | FULL               | OFF (Dev only)    |
| fsync on Commit      | Checkpoint only    | Every Transaction  | OS flush only     |
| Durability Guarantee | Crash-consistent   | Power-loss durable | Process crash only|
| Max Tx Latency (p99) | < 0.8 ms           | 8.0 - 15.0 ms      | < 0.2 ms          |
+----------------------+--------------------+--------------------+-------------------+
```

### 6.1. Pragmas and Operational Configuration
1. `PRAGMA journal_mode = WAL;`  
   Enables concurrent read transactions alongside the active single writer connection without read-write locking conflicts.
2. `PRAGMA synchronous = NORMAL;` (Default)  
   In WAL mode, `NORMAL` ensures that the database file and WAL indexes are never corrupted across application crashes or OS restarts. WAL checkpoints execute full disk syncs (`fsync`), balancing performance and safety.
3. `PRAGMA synchronous = FULL;` (Configurable via `RELAY_STORAGE_SYNC=FULL`)  
   Forces an explicit `fsync` after every individual ledger commit. Recommended for critical production environments with battery-backed write caches or high-value financial actions.
4. `PRAGMA wal_autocheckpoint = 1000;`  
   Automatically checkpoints the WAL file to the main database when the WAL reaches 1000 pages (approx. 4MB).

### 6.2. Crash Recovery Semantics
- **Process Crash (SIGKILL / Panic):** Uncommitted transactions in memory are cleanly dropped. Uncheckpointed commits present in `ledger.db-wal` are automatically replayed and restored by the SQLite engine upon next opening.
- **Power Loss / OS Crash (Default Mode `NORMAL`):** The ledger will recover to the state of the last synchronized WAL checkpoint. Because sequence numbers and hash chain linkages are validated sequentially, any partially written trailing frame at the end of the WAL is detected, truncated, and ignored by SQLite.

---

## 7. Corruption Detection & Recovery Model

Relay treats the audit ledger as a high-integrity forensic log. Any tampering, storage corruption, or missing records triggers an immediate fail-closed state.

```
+-----------------------------------------------------------------------------------------+
|                               CORRUPTION DETECTION MATRIX                               |
+-----------------------+--------------------------+--------------------+-----------------+
| CORRUPTION TYPE       | DETECTION MECHANISM      | SYSTEM BEHAVIOR    | RECOVERY ACTION |
+-----------------------+--------------------------+--------------------+-----------------+
| Modified Receipt Row  | SHA256(Payload) != Hash  | Halts verification | Quarantine DB   |
| Broken Hash Linkage   | H_n != SHA256(H_{n-1}..) | Immediate Error    | Quarantine DB   |
| Missing Sequence Gap  | Seq_n != Seq_{n-1} + 1   | Startup Abort      | Restore Backup  |
| Truncated Database    | SQLite Header / WAL Err  | Auto WAL Recovery  | Repair / Dump   |
| Corrupted DSSE Sig    | Ed25519 Verify Fails     | Action Rejected    | Log Forensic Err|
+-----------------------+--------------------------+--------------------+-----------------+
```

### 7.1. Systematic Verification Algorithm

Relay implements a streaming ledger verification routine (`relay verify-ledger`) executed automatically on daemon startup and on-demand via the CLI.

```rust
// Conceptual Verification Algorithm (Rust)
pub fn verify_ledger_integrity(conn: &rusqlite::Connection) -> Result<VerificationReport, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT l.sequence_number, l.parent_hash, l.payload_hash, l.entry_hash, r.dsse_envelope 
         FROM ledger_entries l
         JOIN receipts r ON l.receipt_id = r.receipt_id
         ORDER BY l.sequence_number ASC"
    )?;

    let mut expected_sequence: u64 = 0;
    let mut expected_parent_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let seq: u64 = row.get(0)?;
        let parent_hash: String = row.get(1)?;
        let payload_hash: String = row.get(2)?;
        let entry_hash: String = row.get(3)?;
        let dsse_bytes: Vec<u8> = row.get(4)?;

        // 1. Verify Sequence Monotonicity
        if seq != expected_sequence {
            return Err(StorageError::SequenceGap { expected: expected_sequence, actual: seq });
        }

        // 2. Verify Parent Hash Linkage
        if parent_hash != expected_parent_hash {
            return Err(StorageError::BrokenHashChain { seq, expected_parent: expected_parent_hash, actual_parent: parent_hash });
        }

        // 3. Verify Payload Hash from Raw Envelope
        let computed_payload_hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &dsse_bytes).as_ref());
        if computed_payload_hash != payload_hash {
            return Err(StorageError::PayloadHashMismatch { seq, computed: computed_payload_hash, recorded: payload_hash });
        }

        // 4. Verify Entry Hash Formulation
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&seq.to_be_bytes());
        hasher.update(&hex::decode(&parent_hash)?);
        hasher.update(&hex::decode(&payload_hash)?);
        let computed_entry_hash = hex::encode(hasher.finish().as_ref());

        if computed_entry_hash != entry_hash {
            return Err(StorageError::EntryHashMismatch { seq, computed: computed_entry_hash, recorded: entry_hash });
        }

        expected_parent_hash = entry_hash;
        expected_sequence += 1;
    }

    Ok(VerificationReport { total_verified_entries: expected_sequence, head_hash: expected_parent_hash })
}
```

### 7.2. Automated Recovery Procedures
1. **Unclean Shutdown Recovery:** On startup, SQLite automatically rolls forward complete transactions from the WAL and discards partial frames.
2. **Hash Chain Discontinuity Action:** If a hash mismatch or missing sequence is detected during startup verification:
   - The Relay daemon **refuses to start** in normal gateway mode.
   - It emits an alert: `FATAL: Cryptographic ledger verification failed at sequence N`.
   - The database is switched to Read-Only Forensic Mode (`PRAGMA query_only = ON;`), preventing further execution until human investigation is performed.

---

## 8. Schema Evolution & Migration Strategy

Relay enforces a forward-only, idempotent migration pipeline managed by a lightweight, zero-dependency migration runner built into the binary.

```
+------------------------------------------------------------------------------------+
|                            SCHEMA MIGRATION PIPELINE                               |
+------------------------------------------------------------------------------------+
| 1. Acquire SQLite exclusive lock (BEGIN IMMEDIATE).                                |
| 2. Query `schema_migrations` table (create if absent).                             |
| 3. Compare embedded migrations array against applied versions.                     |
| 4. Validate SHA-256 checksum of past migrations (halt if modified).                |
| 5. Execute new migrations sequentially inside single transaction.                  |
| 6. Record version, timestamp, and migration script checksum.                       |
| 7. COMMIT; transaction.                                                            |
+------------------------------------------------------------------------------------+
```

### 8.1. Migration Rules & Invariants
1. **Pure Forward Migrations:** No automatic downgrade or down-migrations are supported. Downgrading a binary across a schema version boundary requires restoring a database backup taken prior to the upgrade.
2. **Immutable History:** Past migration SQL files are compiled directly into the Rust binary using `include_str!()`. Their SHA-256 checksums are verified on boot against `schema_migrations`.
3. **Additive Schema Changes:** Future schema revisions must only add nullable columns, new tables, or new non-unique indexes. Modifying or dropping existing ledger columns is prohibited to maintain receipt deserialization guarantees.

### 8.2. Automated Hot Backups
Relay provides an online backup utility using the SQLite Online Backup API:
```bash
relay admin backup --destination /var/backups/relay/ledger-$(date +%s).bak
```
The backup API safely copies pages while the database is actively receiving write transactions without blocking agent operations.

---

## 9. Rust Domain-to-Storage Mapping Architecture

To ensure total separation between domain entities and storage details, Relay implements explicit adapter mappers in `relay_storage::sqlite`.

```rust
// Domain Entity in relay_core (Pure, DB-agnostic)
pub struct ActionReceipt {
    pub receipt_id: ReceiptId,
    pub sequence_number: Option<u64>,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub tool_namespace: ToolNamespace,
    pub tool_name: ToolName,
    pub decision: PolicyDecision,
    pub status: ExecutionStatus,
    pub policy_hash: PolicyHash,
    pub dsse_envelope: DsseEnvelope,
}

// Storage Adapter Entity in relay_storage (SQLite specific)
pub(crate) struct SqliteReceiptRow {
    pub receipt_id: String,
    pub sequence_number: i64,
    pub timestamp_utc: String,
    pub tool_namespace: String,
    pub tool_name: String,
    pub decision: String,
    pub status: String,
    pub policy_hash: String,
    pub dsse_envelope_blob: Vec<u8>,
    pub raw_payload_len: i64,
}

// Explicit Bidirectional Conversion Traits
impl TryFrom<SqliteReceiptRow> for ActionReceipt {
    type Error = StorageConversionError;
    fn try_from(row: SqliteReceiptRow) -> Result<Self, Self::Error> {
        Ok(ActionReceipt {
            receipt_id: ReceiptId::parse(&row.receipt_id)?,
            sequence_number: Some(row.sequence_number as u64),
            timestamp_utc: chrono::DateTime::parse_from_rfc3339(&row.timestamp_utc)?.with_timezone(&chrono::Utc),
            tool_namespace: ToolNamespace::new(row.tool_namespace)?,
            tool_name: ToolName::new(row.tool_name)?,
            decision: PolicyDecision::from_str(&row.decision)?,
            status: ExecutionStatus::from_str(&row.status)?,
            policy_hash: PolicyHash::from_hex(&row.policy_hash)?,
            dsse_envelope: DsseEnvelope::from_slice(&row.dsse_envelope_blob)?,
        })
    }
}
```

---

## 10. Persistence Invariants Checklist

The Relay persistence layer is guaranteed to adhere to the following non-negotiable invariants:

- [x] **INV-STOR-001 (Secret Non-Residency):** Target credentials (API tokens, passwords) are never written to SQLite, WAL logs, temporary files, or unencrypted storage.
- [x] **INV-STOR-002 (Domain Decoupling):** Core domain structs (`Action`, `Receipt`, `Approval`) do not contain SQL annotations, table names, or SQLite crate dependencies.
- [x] **INV-STOR-003 (Ledger Append-Only):** The `ledger_entries` and `receipts` tables reject all SQL `UPDATE` and `DELETE` queries via database triggers and application invariants.
- [x] **INV-STOR-004 (Cryptographic Chaining):** Every ledger entry $n$ strictly binds $H_n = \text{SHA-256}(n \mathbin{\Vert} H_{n-1} \mathbin{\Vert} \text{SHA-256}(\text{Envelope}_n))$.
- [x] **INV-STOR-005 (Monotonic Sequences):** Sequence numbers are strictly incrementing non-negative integers ($0, 1, 2, \dots$) with zero gaps permitted.
- [x] **INV-STOR-006 (Key Isolation):** Node signing private keys reside exclusively in the OS Keyring or encrypted fallback vaults; never in the application database.
- [x] **INV-STOR-007 (Fail-Closed on Corruption):** Any cryptographic discontinuity detected during startup or runtime verification immediately halts gateway operations.
- [x] **INV-STOR-008 (WAL Concurrency):** All writes flow through a dedicated single-writer thread holding an exclusive connection, eliminating lock contention for concurrent readers.

---
*End of Specification.*
