//! Synchronous SQLite storage engine for Relay Ledger.
//!
//! Complies with A006:
//! - Strict WAL mode and normal synchronous durability
//! - Monotonic sequence numbers and hash-chain verification
//! - Defends invariants at the SQLite engine level via triggers

use chrono::Utc;
use relay_domain::{
    ActionReceipt, ApprovalEvidence, Digest, DsseEnvelope, InTotoStatement, LedgerEntry,
    LedgerError, ReceiptId, SequenceNumber,
};
use rusqlite::Connection;
use std::path::Path;

use crate::genesis::ensure_genesis_initialized;
use crate::hash_chain::{compute_entry_hash, compute_payload_hash};
use crate::migrations::apply_migrations;
use crate::models::{LedgerRow, NodeIdentityRecord};

/// Synchronous SQLite persistence engine managing the ledger database
pub struct SqliteStorageEngine {
    conn: Connection,
}

impl SqliteStorageEngine {
    /// Opens or creates a SQLite database at the specified filesystem path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path_ref = path.as_ref();

        // Ensure parent directory exists with 0700 permissions
        if let Some(parent) = path_ref.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = std::fs::DirBuilder::new();
                    builder.recursive(true);
                    builder.mode(0o700);
                    builder.create(parent).map_err(|e| {
                        LedgerError::ConnectionFailed(format!(
                            "Failed to create ledger directory '{parent:?}': {e}"
                        ))
                    })?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        LedgerError::ConnectionFailed(format!(
                            "Failed to create ledger directory '{parent:?}': {e}"
                        ))
                    })?;
                }
            }
        }

        // On Unix, pre-create the SQLite database file with 0600 permissions if it doesn't exist
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            if !path_ref.exists() {
                let _ = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path_ref);
            } else if let Ok(metadata) = std::fs::metadata(path_ref) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path_ref, perms);
            }
        }

        let mut conn = Connection::open(path_ref).map_err(|e| {
            LedgerError::ConnectionFailed(format!(
                "Failed to open SQLite database at '{path_ref:?}': {e}"
            ))
        })?;

        // On Unix, ensure database file permissions remain 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path_ref) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path_ref, perms);
            }
        }

        Self::configure_and_migrate(&mut conn)?;

        Ok(Self { conn })
    }

    /// Opens an in-memory SQLite database (ideal for tests)
    pub fn in_memory() -> Result<Self, LedgerError> {
        let mut conn = Connection::open_in_memory().map_err(|e| {
            LedgerError::ConnectionFailed(format!("Failed to open in-memory SQLite DB: {e}"))
        })?;

        Self::configure_and_migrate(&mut conn)?;

        Ok(Self { conn })
    }

    /// Configures SQLite PRAGMAs and applies schema migrations
    fn configure_and_migrate(conn: &mut Connection) -> Result<(), LedgerError> {
        // Enforce required PRAGMAs (A006 §4.1)
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| LedgerError::ConnectionFailed(format!("Failed to set SQLite PRAGMAs: {e}")))?;

        // Apply migrations
        apply_migrations(conn)?;

        Ok(())
    }

    /// Returns a reference to the underlying rusqlite Connection
    pub fn raw_connection(&self) -> &Connection {
        &self.conn
    }

    /// Returns a mutable reference to the underlying rusqlite Connection
    pub fn raw_connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Ensures the genesis block is initialized with the given node identity
    pub fn initialize_genesis(
        &mut self,
        node_id: &str,
        public_key_hex: &str,
    ) -> Result<LedgerEntry, LedgerError> {
        ensure_genesis_initialized(&mut self.conn, node_id, public_key_hex)
    }

    /// Retrieves node identity information from the ledger
    pub fn get_node_identity(&self) -> Result<Option<NodeIdentityRecord>, LedgerError> {
        let res = self.conn.query_row(
            "SELECT node_id, public_key_hex, key_algorithm, initialized_at, metadata_json
             FROM node_identity LIMIT 1",
            [],
            |row| {
                Ok(NodeIdentityRecord {
                    node_id: row.get(0)?,
                    public_key_hex: row.get(1)?,
                    key_algorithm: row.get(2)?,
                    initialized_at: row.get(3)?,
                    metadata_json: row.get(4)?,
                })
            },
        );

        match res {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LedgerError::QueryError(format!(
                "Failed to query node_identity: {e}"
            ))),
        }
    }

    /// Appends a signed ActionReceipt to the SQLite ledger inside an atomic transaction (A006 §5.3)
    pub fn append(&mut self, receipt: &ActionReceipt) -> Result<LedgerEntry, LedgerError> {
        // Canonicalize DSSE envelope to deterministic JCS bytes (A006 §5.1)
        let canonical_dsse_bytes = serde_jcs::to_vec(&receipt.dsse_envelope).map_err(|e| {
            LedgerError::SerializationError(format!("Failed to canonicalize DSSE envelope: {e}"))
        })?;

        // 1. Begin IMMEDIATE transaction
        self.conn.execute_batch("BEGIN IMMEDIATE;").map_err(|e| {
            LedgerError::WriteError(format!("Failed to begin append transaction: {e}"))
        })?;

        // 2. Read current head entry (sequence n-1 and EntryHash_{n-1})
        let head_query = self.conn.query_row(
            "SELECT sequence_number, entry_hash FROM ledger_entries ORDER BY sequence_number DESC LIMIT 1",
            [],
            |row| {
                let seq: u64 = row.get(0)?;
                let hash: String = row.get(1)?;
                Ok((seq, hash))
            },
        );

        let (prev_seq, prev_entry_hash_hex) = match head_query {
            Ok(res) => res,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                return Err(LedgerError::WriteError(
                    "Ledger uninitialized: Genesis block not found. Call initialize_genesis first."
                        .to_string(),
                ));
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK;");
                return Err(LedgerError::QueryError(format!(
                    "Failed to read ledger head: {e}"
                )));
            }
        };

        let new_sequence = prev_seq + 1;
        let prev_entry_hash = Digest::from_hex(&prev_entry_hash_hex).map_err(|e| {
            let _ = self.conn.execute_batch("ROLLBACK;");
            LedgerError::Corruption(format!("Corrupted head entry_hash hex: {e}"))
        })?;

        // 3. Compute PayloadHash_n and EntryHash_n
        let payload_hash = compute_payload_hash(&canonical_dsse_bytes);
        let entry_hash = compute_entry_hash(new_sequence, &prev_entry_hash, &payload_hash);

        let now_utc = Utc::now().to_rfc3339();
        let receipt_id_str = receipt.receipt_id.to_string();
        let parent_hash_hex = prev_entry_hash.to_hex();
        let payload_hash_hex = payload_hash.to_hex();
        let entry_hash_hex = entry_hash.to_hex();

        // 4. Extract statement metadata for relational indexing
        let mut tool_namespace = "mcp".to_string();
        let mut tool_name = "unknown".to_string();
        let mut decision_str = "Permit".to_string();
        let mut status_str = "Success".to_string();
        let mut policy_hash_hex = receipt.action_hash.to_hex();
        let mut approval_record: Option<ApprovalEvidence> = None;

        if let Ok(statement_bytes) = relay_receipts::base64_decode(&receipt.dsse_envelope.payload) {
            if let Ok(stmt) = serde_json::from_slice::<InTotoStatement>(&statement_bytes) {
                if let Some(ns) = stmt
                    .predicate
                    .canonical_proposal
                    .get("tool_namespace")
                    .and_then(|v| v.as_str())
                {
                    tool_namespace = ns.to_string();
                }
                if let Some(tname) = stmt
                    .predicate
                    .canonical_proposal
                    .get("tool_name")
                    .and_then(|v| v.as_str())
                {
                    tool_name = tname.to_string();
                }
                if let Some(dec) = stmt
                    .predicate
                    .policy_decision
                    .get("decision")
                    .and_then(|v| v.as_str())
                {
                    decision_str = dec.to_string();
                }
                if let Some(st) = stmt
                    .predicate
                    .observation
                    .get("status")
                    .and_then(|v| v.as_str())
                {
                    status_str = st.to_string();
                }
                if let Some(ph) = stmt
                    .predicate
                    .policy_decision
                    .get("policy_digest")
                    .and_then(|v| v.as_str())
                {
                    policy_hash_hex = ph.to_string();
                }
                if let Some(app_val) = stmt.predicate.approval {
                    if let Ok(app) = serde_json::from_value::<ApprovalEvidence>(app_val) {
                        approval_record = Some(app);
                    }
                }
            }
        }

        // 5. Ensure policy snapshot exists for foreign key constraint
        self.conn
            .execute(
                "INSERT OR IGNORE INTO policy_snapshots (policy_hash, cedar_bundle, created_at_utc)
                 VALUES (?1, '// Policy Snapshot at Action Receipt Creation', ?2)",
                rusqlite::params![policy_hash_hex, now_utc],
            )
            .map_err(|e| {
                let _ = self.conn.execute_batch("ROLLBACK;");
                LedgerError::WriteError(format!("Failed to insert policy_snapshot: {e}"))
            })?;

        // 6. Insert into ledger_entries
        self.conn
            .execute(
                "INSERT INTO ledger_entries (sequence_number, receipt_id, timestamp_utc, parent_hash, payload_hash, entry_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    new_sequence,
                    receipt_id_str,
                    now_utc,
                    parent_hash_hex,
                    payload_hash_hex,
                    entry_hash_hex,
                ],
            )
            .map_err(|e| {
                let _ = self.conn.execute_batch("ROLLBACK;");
                LedgerError::WriteError(format!("Failed to insert ledger_entries: {e}"))
            })?;

        // 7. Insert into receipts
        self.conn
            .execute(
                "INSERT INTO receipts (receipt_id, sequence_number, timestamp_utc, tool_namespace, tool_name, decision, status, policy_hash, dsse_envelope, raw_payload_len)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    receipt_id_str,
                    new_sequence,
                    now_utc,
                    tool_namespace,
                    tool_name,
                    decision_str,
                    status_str,
                    policy_hash_hex,
                    canonical_dsse_bytes,
                    canonical_dsse_bytes.len(),
                ],
            )
            .map_err(|e| {
                let _ = self.conn.execute_batch("ROLLBACK;");
                LedgerError::WriteError(format!("Failed to insert receipts row: {e}"))
            })?;

        // 8. If approval evidence was present, insert into approvals
        if let Some(app) = approval_record {
            let _ = self.conn.execute(
                "INSERT OR IGNORE INTO approvals (approval_id, receipt_id, nonce, approver_id, channel, decision, decided_at_utc, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '{}')",
                rusqlite::params![
                    app.approval_id,
                    receipt_id_str,
                    format!("nonce-{}", app.approval_id),
                    app.approver,
                    app.mechanism,
                    app.decision,
                    app.approved_at.to_rfc3339(),
                ],
            );
        }

        // 9. Commit transaction
        self.conn.execute_batch("COMMIT;").map_err(|e| {
            LedgerError::WriteError(format!("Failed to commit append transaction: {e}"))
        })?;

        Ok(LedgerEntry {
            sequence_number: SequenceNumber(new_sequence),
            session_id: receipt.session_id,
            action_id: receipt.action_id,
            action_hash: receipt.action_hash,
            receipt_id: receipt.receipt_id,
            receipt_hash: payload_hash,
            previous_receipt_hash: prev_entry_hash,
            entry_hash,
            dsse_envelope: receipt.dsse_envelope.clone(),
            recorded_at: Utc::now(),
        })
    }

    /// Retrieves an entry by its sequence number
    pub fn get_by_sequence(&self, seq: SequenceNumber) -> Result<Option<LedgerEntry>, LedgerError> {
        let res = self.conn.query_row(
            "SELECT l.sequence_number, l.receipt_id, l.timestamp_utc, l.parent_hash, l.payload_hash,
                    l.entry_hash, r.tool_namespace, r.tool_name, r.decision, r.status, r.policy_hash, r.dsse_envelope
             FROM ledger_entries l
             JOIN receipts r ON l.receipt_id = r.receipt_id
             WHERE l.sequence_number = ?1",
            rusqlite::params![seq.as_u64()],
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

        match res {
            Ok(row) => Ok(Some(row.to_domain_ledger_entry()?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LedgerError::QueryError(format!(
                "Query failed for sequence {}: {e}",
                seq.as_u64()
            ))),
        }
    }

    /// Retrieves an entry by receipt ID
    pub fn get_by_receipt_id(&self, id: &ReceiptId) -> Result<Option<LedgerEntry>, LedgerError> {
        let res = self.conn.query_row(
            "SELECT l.sequence_number, l.receipt_id, l.timestamp_utc, l.parent_hash, l.payload_hash,
                    l.entry_hash, r.tool_namespace, r.tool_name, r.decision, r.status, r.policy_hash, r.dsse_envelope
             FROM ledger_entries l
             JOIN receipts r ON l.receipt_id = r.receipt_id
             WHERE l.receipt_id = ?1",
            rusqlite::params![id.to_string()],
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

        match res {
            Ok(row) => Ok(Some(row.to_domain_ledger_entry()?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LedgerError::QueryError(format!(
                "Query failed for receipt_id {id}: {e}"
            ))),
        }
    }

    /// Retrieves full ActionReceipt by receipt ID
    pub fn get_receipt_by_id(&self, id: &ReceiptId) -> Result<Option<ActionReceipt>, LedgerError> {
        let res = self.conn.query_row(
            "SELECT r.receipt_id, r.sequence_number, r.timestamp_utc, r.dsse_envelope, l.parent_hash, l.payload_hash
             FROM receipts r
             JOIN ledger_entries l ON r.receipt_id = l.receipt_id
             WHERE r.receipt_id = ?1",
            rusqlite::params![id.to_string()],
            |row| {
                let r_id: String = row.get(0)?;
                let _seq: u64 = row.get(1)?;
                let ts: String = row.get(2)?;
                let blob: Vec<u8> = row.get(3)?;
                let parent_hex: String = row.get(4)?;
                let payload_hex: String = row.get(5)?;
                Ok((r_id, ts, blob, parent_hex, payload_hex))
            },
        );

        match res {
            Ok((r_id_str, ts_str, blob, parent_hex, payload_hex)) => {
                let receipt_id = r_id_str.parse::<ReceiptId>().map_err(|e| {
                    LedgerError::Corruption(format!("Corrupted receipt ID in DB: {e}"))
                })?;
                let envelope: DsseEnvelope = serde_json::from_slice(&blob).map_err(|e| {
                    LedgerError::Corruption(format!("Corrupted DSSE envelope in DB: {e}"))
                })?;
                let parent_hash = Digest::from_hex(&parent_hex)
                    .map_err(|e| LedgerError::Corruption(format!("Corrupted parent hash: {e}")))?;
                let receipt_hash = Digest::from_hex(&payload_hex)
                    .map_err(|e| LedgerError::Corruption(format!("Corrupted payload hash: {e}")))?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                // Extract action_id and session_id from envelope statement
                let mut action_id = relay_domain::ActionId::from_uuid(uuid::Uuid::nil());
                let mut session_id = relay_domain::SessionId::from_uuid(uuid::Uuid::nil());
                let mut action_hash = relay_domain::ActionHash::compute(b"");

                if let Ok(statement_bytes) = relay_receipts::base64_decode(&envelope.payload) {
                    if let Ok(stmt) = serde_json::from_slice::<InTotoStatement>(&statement_bytes) {
                        action_id = stmt.predicate.action_id;
                        session_id = stmt.predicate.session_id;
                        action_hash = stmt.predicate.action_hash;
                    }
                }

                Ok(Some(ActionReceipt {
                    receipt_id,
                    action_id,
                    session_id,
                    action_hash,
                    receipt_hash,
                    parent_receipt_hash: parent_hash,
                    dsse_envelope: envelope,
                    created_at,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LedgerError::QueryError(format!(
                "Query failed for receipt_id {id}: {e}"
            ))),
        }
    }

    /// Returns the total count of entries in the ledger
    pub fn count(&self) -> Result<u64, LedgerError> {
        self.conn
            .query_row("SELECT count(*) FROM ledger_entries", [], |row| row.get(0))
            .map_err(|e| LedgerError::QueryError(format!("Count query failed: {e}")))
    }

    /// Lists the most recent N ledger entries
    pub fn list_recent(&self, limit: usize) -> Result<Vec<LedgerEntry>, LedgerError> {
        let mut stmt = self.conn.prepare(
            "SELECT l.sequence_number, l.receipt_id, l.timestamp_utc, l.parent_hash, l.payload_hash,
                    l.entry_hash, r.tool_namespace, r.tool_name, r.decision, r.status, r.policy_hash, r.dsse_envelope
             FROM ledger_entries l
             JOIN receipts r ON l.receipt_id = r.receipt_id
             ORDER BY l.sequence_number DESC
             LIMIT ?1",
        )
        .map_err(|e| LedgerError::QueryError(format!("Prepare list_recent failed: {e}")))?;

        let rows = stmt
            .query_map(rusqlite::params![limit], |row| {
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
            })
            .map_err(|e| LedgerError::QueryError(format!("Query list_recent failed: {e}")))?;

        let mut entries = Vec::new();
        for item in rows {
            let row = item.map_err(|e| LedgerError::QueryError(e.to_string()))?;
            entries.push(row.to_domain_ledger_entry()?);
        }
        Ok(entries)
    }

    /// Returns the latest entry hash in the ledger
    pub fn get_latest_entry_hash(&self) -> Result<Digest, LedgerError> {
        let res = self.conn.query_row(
            "SELECT entry_hash FROM ledger_entries ORDER BY sequence_number DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        );

        match res {
            Ok(hex_str) => Digest::from_hex(&hex_str).map_err(|e| {
                LedgerError::Corruption(format!("Invalid latest entry hash hex: {e}"))
            }),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(LedgerError::QueryError("Ledger is empty".to_string()))
            }
            Err(e) => Err(LedgerError::QueryError(format!(
                "Failed to get latest entry hash: {e}"
            ))),
        }
    }

    /// Returns the latest payload receipt hash in the ledger
    pub fn get_latest_receipt_hash(&self) -> Result<Digest, LedgerError> {
        let res = self.conn.query_row(
            "SELECT payload_hash FROM ledger_entries ORDER BY sequence_number DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        );

        match res {
            Ok(hex_str) => Digest::from_hex(&hex_str).map_err(|e| {
                LedgerError::Corruption(format!("Invalid latest payload hash hex: {e}"))
            }),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(LedgerError::QueryError("Ledger is empty".to_string()))
            }
            Err(e) => Err(LedgerError::QueryError(format!(
                "Failed to get latest receipt hash: {e}"
            ))),
        }
    }
}
