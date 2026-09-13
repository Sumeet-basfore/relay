# Milestone B008: Local SQLite Evidence Ledger

**Status:** Completed & Verified  
**Milestone:** B008  
**Specification References:** [R011 Action Receipts](../research/R011-action-receipts.md), [R015 Build Gate](../research/R015-build-gate.md), [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A006 Persistence & Storage](../architecture/A006-persistence-and-storage.md), [A008 Dependency Architecture](../architecture/A008-rust-dependency-architecture.md), [A010 Build Specification](../architecture/A010-build-specification.md)  
**Implementation Crates:** `crates/relay-ledger`, `crates/relay-domain`, `crates/relay-cli`

---

## 1. Executive Summary

Milestone B008 implements Relay's **Local SQLite Evidence Ledger Subsystem**.

In autonomous agent governance, signed evidence artifacts (Action Receipts from B007) are only as useful as the durability, immutability, and tamper-evidence of their storage substrate. If a compromised host or rogue process can delete past actions, reorder log entries, or alter evidence without detection, forensic accountability is lost.

Relay B008 solves this problem by providing a local-first, append-only, mathematically chained SQLite evidence ledger (`ledger.db`) paired with an independent offline forensic verification engine (`relay verify` / `relay verify-ledger`).

```text
+----------------------------------------------------------------------------------------------------+
|                                  B008 PERSISTENCE & LEDGER PIPELINE                                |
|                                                                                                    |
|  [Signed ActionReceipt] (DSSE in-toto Statement from B007)                                         |
|         │                                                                                          |
|         ▼                                                                                          |
|  [SqliteLedger::append()] ──► [mpsc::channel(1024)] ──► [Storage Engine Actor Thread]               |
|                                                               │                                    |
|                                                               ▼ (BEGIN IMMEDIATE)                  |
|                                                     [Read Current Head]                            |
|                                                     (seq n-1, EntryHash_{n-1})                     |
|                                                               │                                    |
|                                                               ▼                                    |
|                                                    [Compute Cryptographic Hashes]                  |
|                                                    • PayloadHash_n = SHA256(CanonicalDSSE_n)       |
|                                                    • EntryHash_n = SHA256(BE_U64(n) ||             |
|                                                                           Parent ||                |
|                                                                           Payload)                 |
|                                                               │                                    |
|                                                               ▼                                    |
|                                                    [Atomic SQLite Insertions]                      |
|                                                    1. INSERT INTO policy_snapshots                 |
|                                                    2. INSERT INTO ledger_entries                   |
|                                                    3. INSERT INTO receipts                         |
|                                                    4. INSERT INTO approvals (if req)               |
|                                                               │                                    |
|                                                               ▼                                    |
|                                                    [COMMIT Transaction]                            |
|                                                               │                                    |
|                                                               ▼                                    |
|                                                 [SQLite WAL Main DB File]                          |
|                                                  (PRAGMA journal_mode=WAL)                         |
|                                                  (PRAGMA synchronous=NORMAL)                       |
|                                                  (Immutability Triggers Active)                    |
|                                                               │                                    |
|                                                               ▼                                    |
|                                         [Offline Forensic Verification Engine]                     |
|                                            `relay verify` / `LedgerVerifier`                       |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Hash Chain Mathematics

Relay enforces a strict, mathematical hash chain linking every governed action sequentially from the genesis block to the latest head entry ([A006 §5.1, §5.2](../architecture/A006-persistence-and-storage.md)).

### 2.1. Exact Mathematical Chaining Rule

For any given ledger entry $n \ge 1$:

1. **Payload Hash Formulation:**
   $$\text{PayloadHash}_n = \text{SHA-256}(\text{CanonicalDSSEBytes}_n)$$
   where $\text{CanonicalDSSEBytes}_n$ represents the RFC 8785 JSON Canonicalization Scheme (JCS) deterministic serialization of the DSSE Envelope containing the signed Action Receipt.

2. **Ledger Node Entry Hash Formulation:**
   $$\text{EntryHash}_n = \text{SHA-256}\Big(\text{BE\_U64}(n) \mathbin{\Vert} \text{Bytes}(\text{ParentHash}_{n-1}) \mathbin{\Vert} \text{Bytes}(\text{PayloadHash}_n)\Big)$$
   - $\text{BE\_U64}(n)$: 8-byte big-endian representation of the sequence number $n$.
   - $\text{Bytes}(\text{ParentHash}_{n-1})$: 32 raw bytes derived from the 64-character lowercase hex string of entry $n-1$.
   - $\text{Bytes}(\text{PayloadHash}_n)$: 32 raw bytes of the SHA-256 digest of the DSSE envelope.

Total input to the entry hasher is exactly $8 + 32 + 32 = 72$ bytes, ensuring fixed-length pre-image security and zero ambiguity.

### 2.2. Genesis Block Formulation ($n = 0$)

The Genesis Block initializes the cryptographic ledger upon first boot ([A006 §5.2](../architecture/A006-persistence-and-storage.md)):

$$\text{GenesisSequence} = 0$$
$$\text{GenesisParentHash} = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$
$$\text{GenesisPayload} = \text{JCS}\big(\{\text{"node_id"}: \text{NODE\_UUID}, \text{"system"}: \text{"RELAY_GATEWAY_GENESIS"}, \text{"version"}: \text{"1.0.0"}\}\big)$$
$$\text{GenesisPayloadHash} = \text{SHA-256}(\text{GenesisPayload})$$
$$\text{GenesisEntryHash} = \text{SHA-256}\Big(\text{BE\_U64}(0) \mathbin{\Vert} \text{Bytes}(0^{32}) \mathbin{\Vert} \text{Bytes}(\text{GenesisPayloadHash})\Big)$$

---

## 3. Relational Schema & Immutability Triggers

The relational schema is defined in `crates/relay-ledger/src/schema.sql` and managed via a pure forward migration runner with SHA-256 script integrity checksum verification:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

-- 1. Schema Migrations Ledger
CREATE TABLE IF NOT EXISTS schema_migrations (
    version         INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    applied_at_utc  TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL
);

-- 2. Node Identity Table
CREATE TABLE IF NOT EXISTS node_identity (
    node_id         TEXT PRIMARY KEY,
    public_key_hex  TEXT NOT NULL,
    key_algorithm   TEXT NOT NULL DEFAULT 'ed25519',
    initialized_at  TEXT NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);

-- 3. Policy Snapshots Table
CREATE TABLE IF NOT EXISTS policy_snapshots (
    policy_hash     TEXT PRIMARY KEY,
    cedar_bundle    TEXT NOT NULL,
    created_at_utc  TEXT NOT NULL
);

-- 4. Cryptographic Ledger Entries Table
CREATE TABLE IF NOT EXISTS ledger_entries (
    sequence_number INTEGER PRIMARY KEY,
    receipt_id      TEXT NOT NULL UNIQUE,
    timestamp_utc   TEXT NOT NULL,
    parent_hash     TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    entry_hash      TEXT NOT NULL UNIQUE,
    CONSTRAINT check_hashes_hex CHECK (
        length(parent_hash) = 64 AND 
        length(payload_hash) = 64 AND 
        length(entry_hash) = 64
    )
);

-- 5. Action Receipts Table
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id          TEXT PRIMARY KEY,
    sequence_number     INTEGER NOT NULL UNIQUE,
    timestamp_utc       TEXT NOT NULL,
    tool_namespace      TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    decision            TEXT NOT NULL,
    status              TEXT NOT NULL,
    policy_hash         TEXT NOT NULL,
    dsse_envelope       BLOB NOT NULL,
    raw_payload_len     INTEGER NOT NULL,
    FOREIGN KEY (sequence_number) REFERENCES ledger_entries(sequence_number) ON DELETE RESTRICT,
    FOREIGN KEY (receipt_id) REFERENCES ledger_entries(receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (policy_hash) REFERENCES policy_snapshots(policy_hash) ON DELETE RESTRICT
);

-- 6. Approvals Table
CREATE TABLE IF NOT EXISTS approvals (
    approval_id         TEXT PRIMARY KEY,
    receipt_id          TEXT NOT NULL,
    nonce               TEXT NOT NULL UNIQUE,
    approver_id         TEXT NOT NULL,
    channel             TEXT NOT NULL,
    decision            TEXT NOT NULL,
    decided_at_utc      TEXT NOT NULL,
    metadata_json       TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (receipt_id) REFERENCES receipts(receipt_id) ON DELETE RESTRICT
);
```

### Defense-in-Depth Immutability Triggers (INV-STOR-003)

To prevent accidental modification or deletion by application code or direct SQLite clients, Relay installs database-level triggers that abort `UPDATE` and `DELETE` queries with fatal invariant violation messages:

```sql
CREATE TRIGGER IF NOT EXISTS prevent_ledger_update
BEFORE UPDATE ON ledger_entries
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: ledger_entries is strictly append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_ledger_delete
BEFORE DELETE ON ledger_entries
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: ledger_entries rows cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS prevent_receipts_update
BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: receipts are cryptographically immutable');
END;

CREATE TRIGGER IF NOT EXISTS prevent_receipts_delete
BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(FAIL, 'RELAY_STORAGE_INVARIANT_VIOLATION: receipts cannot be deleted');
END;
```

---

## 4. Concurrency & Durability Architecture

Relay uses an asymmetric concurrency architecture ([A006 §5.3](../architecture/A006-persistence-and-storage.md)):

1. **Dedicated Single-Writer Actor Thread:**
   - All async Tokio worker tasks submit `Append`, `Query`, and `Verify` commands through a bounded `tokio::sync::mpsc::channel(1024)` to a dedicated OS thread (`relay-sqlite-ledger-writer`).
   - The thread holds exclusive ownership of the single writer SQLite `rusqlite::Connection`, eliminating lock thrashing, `SQLITE_BUSY` errors, and sequence collisions.
2. **Transaction Isolation:**
   - Appends execute within `BEGIN IMMEDIATE; ... COMMIT;`.
   - Sequence increments and parent hash linkages are strictly serialized.
3. **Write-Ahead Logging (WAL) Mode:**
   - `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = NORMAL;`.
   - Allows concurrent reads without blocking in-flight writes.
   - Automatically recovers from process crashes and OS restarts.

---

## 5. Offline Forensic Verification Engine (`LedgerVerifier`)

The forensic verification engine streams rows sequentially from genesis to head and evaluates six validation checks:

```rust
pub fn verify_connection(
    conn: &Connection,
    public_key: Option<&[u8; 32]>,
    from_seq: Option<u64>,
) -> Result<LedgerVerificationReport, LedgerError>
```

### Verification Checks:
1. **Sequence Monotonicity:** $S_n == S_{n-1} + 1$ (fails with `SequenceGap` if any row is missing or out-of-order).
2. **Parent Hash Linkage:** $\text{ParentHash}_n == \text{EntryHash}_{n-1}$ (fails with `BrokenChain` if predecessor hash is altered).
3. **Payload Hash Integrity:** $\text{SHA-256}(\text{CanonicalDSSEBytes}_n) == \text{PayloadHash}_n$ (fails with `PayloadHashMismatch` if envelope bytes are modified).
4. **Entry Hash Formulation:** $\text{SHA-256}(\text{BE\_U64}(n) \mathbin{\Vert} \text{Parent} \mathbin{\Vert} \text{Payload}) == \text{EntryHash}_n$ (fails with `EntryHashMismatch`).
5. **Digital Signature Verification:** Reconstructs DSSE PAE and verifies Ed25519 signature against public key (fails with `InvalidSignature`).
6. **in-toto Statement Integrity:** Validates statement schema compliance and ensures `statement.predicate.receipt_id == ledger.receipt_id`.

---

## 6. CLI Surface & Integration

Milestone B008 activates the CLI commands in `relay-cli`:

### `relay verify` / `relay verify-ledger`
```bash
relay verify [--db-path <PATH>] [--from <SEQ>] [--pubkey <PATH>] [--json]
relay verify-ledger [--db-path <PATH>]
```

**Human-Readable Output:**
```text
==================================================
   Relay Cryptographic Ledger Verification
==================================================
Ledger Database:  .relay/ledger.db
Verified At:      2026-09-13T19:40:00Z
Verification Time: 3 ms
Total Entries:    16
Head Sequence:    #15
Genesis Hash:     a1b2c3d4e5...
Head Entry Hash:  f8e9a0b1c2...
Status:           ✓ VALID (Hash chain and signatures verified)
==================================================
```

### `relay receipt get` & `relay receipt list`
```bash
relay receipt get <RECEIPT_ID> [--db-path <PATH>] [--json]
relay receipt list [--limit <N>] [--db-path <PATH>] [--json]
```

---

## 7. Security Invariants Checklist

| Invariant | Description | Verification Status |
|:---|:---|:---|
| **INV-STOR-001 (SI-007)** | **Zero Secrets in Persistence:** API tokens, passwords, private keys never enter SQLite tables or WAL files. | **VERIFIED** (`secret_persistence_tests.rs`) |
| **INV-STOR-002** | **Domain Decoupling:** Core domain structs remain pure and database-agnostic. | **VERIFIED** (`relay-domain`) |
| **INV-STOR-003** | **Ledger Append-Only:** SQL triggers reject `UPDATE` and `DELETE` on `ledger_entries` and `receipts`. | **VERIFIED** (`append_tests.rs`) |
| **INV-STOR-004 (SI-009)** | **Cryptographic Chaining:** $H_n = \text{SHA-256}(\text{Seq}_n \mathbin{\Vert} H_{n-1} \mathbin{\Vert} \text{SHA-256}(\text{Envelope}_n))$. | **VERIFIED** (`hash_chain_tests.rs`) |
| **INV-STOR-005** | **Monotonic Sequences:** Contiguous 0-based sequence numbers with zero gaps permitted. | **VERIFIED** (`concurrency_tests.rs`) |
| **INV-STOR-006** | **Key Isolation:** Signing private keys reside exclusively in secure memory / OS keyring; never in SQLite. | **VERIFIED** (`crates/relay-receipts`, `crates/relay-ledger`) |
| **INV-STOR-007** | **Fail-Closed on Tampering:** Any bit flipped in database immediately triggers verification failure. | **VERIFIED** (`tamper_detection_tests.rs`, `ledger_cli_tests.rs`) |
| **INV-STOR-008** | **Single-Writer Concurrency:** Bounded actor channel eliminates lock contention. | **VERIFIED** (`concurrency_tests.rs`) |

---

## 8. Verification Results

```text
cargo test --workspace
```

- `relay-domain`: 13 tests passed
- `relay-canonical`: 85 tests passed
- `relay-policy`: 26 tests passed
- `relay-credentials`: 45 tests passed
- `relay-receipts`: 40 tests passed
- `relay-connectors`: 55 tests passed
- `relay-mcp`: 15 tests passed
- `relay-ledger`: 23 tests passed (Genesis, Append, Triggers, Concurrency, Durability, Tamper Detection, Microbenchmarks, Integration)
- `relay-cli`: 14 tests passed (CLI help, doctor, MCP governance, verify, verify-ledger, receipt get/list)
- **Total Tests Passing:** 307
- **Compiler Warnings:** 0 (`-D warnings` enforced)
- **Formatting:** 100% compliant (`cargo fmt --check`)
