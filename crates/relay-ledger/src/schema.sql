-- Relay SQLite Ledger Schema Migration V001
-- Strict append-only hash chain and audit storage
-- Complies with A006 Persistence & Storage Architecture Specification

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

-- Indexes for Sub-Millisecond Verification and Query Performance
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger_entries(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_receipts_tool ON receipts(tool_namespace, tool_name);
CREATE INDEX IF NOT EXISTS idx_receipts_decision ON receipts(decision, status);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_approvals_receipt ON approvals(receipt_id);

-- Immutability Triggers (Defense-in-Depth: INV-STOR-003)
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
