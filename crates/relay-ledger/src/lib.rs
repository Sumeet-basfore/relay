//! SQLite append-only hash-chained action receipt ledger for Relay.
//!
//! Complies with:
//! - `A006: Persistence & Storage Architecture Specification`
//! - `A010: Build Specification (Milestone B008)`

pub mod engine;
pub mod genesis;
pub mod hash_chain;
pub mod ledger;
pub mod migrations;
pub mod models;
pub mod verifier;

pub use engine::SqliteStorageEngine;
pub use genesis::ensure_genesis_initialized;
pub use hash_chain::{compute_entry_hash, compute_payload_hash, genesis_parent_hash};
pub use ledger::SqliteLedger;
pub use models::{ApprovalRecord, LedgerRow, NodeIdentityRecord, PolicySnapshotRecord};
pub use verifier::{LedgerVerificationReport, LedgerVerificationStatus, LedgerVerifier};

use async_trait::async_trait;
use chrono::Utc;
use relay_domain::{ActionReceipt, Digest, Ledger, LedgerEntry, LedgerError, SequenceNumber};

/// In-memory ledger foundation for fast testing without SQLite
pub struct MemoryLedger {
    entries: std::sync::RwLock<Vec<LedgerEntry>>,
}

impl MemoryLedger {
    pub fn new() -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
        }
    }
}

impl Default for MemoryLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Ledger for MemoryLedger {
    async fn append(&self, receipt: &ActionReceipt) -> Result<LedgerEntry, LedgerError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| LedgerError::WriteError(format!("Failed to acquire write lock: {e}")))?;

        let seq = SequenceNumber((entries.len() as u64) + 1);
        let prev_hash = if let Some(last) = entries.last() {
            last.entry_hash
        } else {
            hash_chain::genesis_parent_hash()
        };

        let canonical_dsse_bytes = serde_jcs::to_vec(&receipt.dsse_envelope).map_err(|e| {
            LedgerError::SerializationError(format!("Failed to canonicalize DSSE envelope: {e}"))
        })?;
        let payload_hash = hash_chain::compute_payload_hash(&canonical_dsse_bytes);
        let entry_hash = hash_chain::compute_entry_hash(seq.as_u64(), &prev_hash, &payload_hash);

        let entry = LedgerEntry {
            sequence_number: seq,
            session_id: receipt.session_id,
            action_id: receipt.action_id,
            action_hash: receipt.action_hash,
            receipt_id: receipt.receipt_id,
            receipt_hash: payload_hash,
            previous_receipt_hash: prev_hash,
            entry_hash,
            dsse_envelope: receipt.dsse_envelope.clone(),
            recorded_at: Utc::now(),
        };

        entries.push(entry.clone());
        Ok(entry)
    }

    async fn get_by_sequence(
        &self,
        seq: SequenceNumber,
    ) -> Result<Option<LedgerEntry>, LedgerError> {
        let entries = self
            .entries
            .read()
            .map_err(|e| LedgerError::QueryError(format!("Failed to acquire read lock: {e}")))?;

        let idx = (seq.as_u64().saturating_sub(1)) as usize;
        Ok(entries.get(idx).cloned())
    }

    async fn verify_chain(&self) -> Result<bool, LedgerError> {
        let entries = self
            .entries
            .read()
            .map_err(|e| LedgerError::QueryError(format!("Failed to acquire read lock: {e}")))?;

        let mut expected_prev = hash_chain::genesis_parent_hash();
        for entry in entries.iter() {
            if entry.previous_receipt_hash != expected_prev {
                return Err(LedgerError::HashChainBroken {
                    sequence_number: entry.sequence_number.as_u64(),
                    expected_prev: expected_prev.to_hex(),
                    actual_prev: entry.previous_receipt_hash.to_hex(),
                });
            }
            expected_prev = entry.entry_hash;
        }

        Ok(true)
    }

    async fn get_latest_receipt_hash(&self) -> Result<Digest, LedgerError> {
        let entries = self
            .entries
            .read()
            .map_err(|e| LedgerError::QueryError(format!("Failed to acquire read lock: {e}")))?;

        if let Some(last) = entries.last() {
            Ok(last.receipt_hash)
        } else {
            Ok(hash_chain::genesis_parent_hash())
        }
    }
}
