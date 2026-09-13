//! Genesis block creation and node identity initialization.
//!
//! Complies with A006 §5.2: Deterministic Genesis initialization.

use chrono::{DateTime, Utc};
use relay_domain::{LedgerEntry, LedgerError, ReceiptId, SequenceNumber};
use rusqlite::Connection;

use crate::hash_chain::{
    compute_genesis_block, genesis_parent_hash, GENESIS_PARENT_HASH_HEX, GENESIS_SEQUENCE,
};
use crate::models::LedgerRow;

pub const GENESIS_RECEIPT_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Initializes the genesis block and node identity record if not present.
/// If already initialized, returns the existing genesis LedgerEntry.
pub fn ensure_genesis_initialized(
    conn: &mut Connection,
    node_id: &str,
    public_key_hex: &str,
) -> Result<LedgerEntry, LedgerError> {
    // Check if genesis already exists
    let existing_row: Result<LedgerRow, rusqlite::Error> = conn.query_row(
        "SELECT l.sequence_number, l.receipt_id, l.timestamp_utc, l.parent_hash, l.payload_hash,
                l.entry_hash, r.tool_namespace, r.tool_name, r.decision, r.status, r.policy_hash, r.dsse_envelope
         FROM ledger_entries l
         JOIN receipts r ON l.receipt_id = r.receipt_id
         WHERE l.sequence_number = ?1",
        rusqlite::params![GENESIS_SEQUENCE],
        |row| {
            Ok(LedgerRow {
                sequence_number: row.get(0)?,
                receipt_id: row.get(1)?,
                timestamp_utc: row.get(2)?,
                parent_hash: row.get(3)?,
                payload_hash: row.get(4)?,
                entry_hash: row.get(5)?,
                tool_namespace: row.get(6)?,
                tool_name: row.get(7)?,
                decision: row.get(8)?,
                status: row.get(9)?,
                policy_hash: row.get(10)?,
                dsse_envelope: row.get(11)?,
            })
        },
    );

    if let Ok(row) = existing_row {
        return row.to_domain_ledger_entry();
    }

    // Begin immediate transaction for genesis initialization
    conn.execute_batch("BEGIN IMMEDIATE;").map_err(|e| {
        LedgerError::WriteError(format!("Failed to begin genesis transaction: {e}"))
    })?;

    let now_utc = Utc::now().to_rfc3339();

    // 1. Record node identity
    conn.execute(
        "INSERT OR IGNORE INTO node_identity (node_id, public_key_hex, key_algorithm, initialized_at, metadata_json)
         VALUES (?1, ?2, 'ed25519', ?3, '{}')",
        rusqlite::params![node_id, public_key_hex, now_utc],
    )
    .map_err(|e| {
        let _ = conn.execute_batch("ROLLBACK;");
        LedgerError::WriteError(format!("Failed to insert node_identity: {e}"))
    })?;

    // 2. Compute genesis block hashes
    let (payload_bytes, payload_hash, entry_hash) = match compute_genesis_block(node_id) {
        Ok(res) => res,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(e);
        }
    };

    let policy_hash_hex = payload_hash.to_hex();
    let parent_hash_hex = GENESIS_PARENT_HASH_HEX.to_string();
    let payload_hash_hex = payload_hash.to_hex();
    let entry_hash_hex = entry_hash.to_hex();

    // 3. Record genesis policy snapshot
    conn.execute(
        "INSERT OR IGNORE INTO policy_snapshots (policy_hash, cedar_bundle, created_at_utc)
         VALUES (?1, '// Relay Genesis Root Policy\npermit(principal, action, resource);', ?2)",
        rusqlite::params![policy_hash_hex, now_utc],
    )
    .map_err(|e| {
        let _ = conn.execute_batch("ROLLBACK;");
        LedgerError::WriteError(format!("Failed to insert genesis policy_snapshot: {e}"))
    })?;

    // 4. Insert into ledger_entries
    conn.execute(
        "INSERT INTO ledger_entries (sequence_number, receipt_id, timestamp_utc, parent_hash, payload_hash, entry_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            GENESIS_SEQUENCE,
            GENESIS_RECEIPT_ID,
            now_utc,
            parent_hash_hex,
            payload_hash_hex,
            entry_hash_hex,
        ],
    )
    .map_err(|e| {
        let _ = conn.execute_batch("ROLLBACK;");
        LedgerError::WriteError(format!("Failed to insert genesis ledger_entry: {e}"))
    })?;

    // 5. Insert into receipts
    conn.execute(
        "INSERT INTO receipts (receipt_id, sequence_number, timestamp_utc, tool_namespace, tool_name, decision, status, policy_hash, dsse_envelope, raw_payload_len)
         VALUES (?1, ?2, ?3, 'system', 'genesis', 'Permit', 'Success', ?4, ?5, ?6)",
        rusqlite::params![
            GENESIS_RECEIPT_ID,
            GENESIS_SEQUENCE,
            now_utc,
            policy_hash_hex,
            payload_bytes,
            payload_bytes.len(),
        ],
    )
    .map_err(|e| {
        let _ = conn.execute_batch("ROLLBACK;");
        LedgerError::WriteError(format!("Failed to insert genesis receipt: {e}"))
    })?;

    // Commit genesis transaction
    conn.execute_batch("COMMIT;").map_err(|e| {
        LedgerError::WriteError(format!("Failed to commit genesis transaction: {e}"))
    })?;

    Ok(LedgerEntry {
        sequence_number: SequenceNumber(GENESIS_SEQUENCE),
        session_id: relay_domain::SessionId::from_uuid(uuid::Uuid::nil()),
        action_id: relay_domain::ActionId::from_uuid(uuid::Uuid::nil()),
        action_hash: relay_domain::ActionHash::compute(&payload_bytes),
        receipt_id: ReceiptId::from_uuid(uuid::Uuid::nil()),
        receipt_hash: payload_hash,
        previous_receipt_hash: genesis_parent_hash(),
        entry_hash,
        dsse_envelope: relay_domain::DsseEnvelope {
            payload_type: "application/vnd.relay.genesis+json".to_string(),
            payload: hex::encode(&payload_bytes),
            signatures: Vec::new(),
        },
        recorded_at: DateTime::parse_from_rfc3339(&now_utc)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}
