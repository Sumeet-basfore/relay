//! Storage adapter models and conversion traits for Relay SQLite persistence.
//!
//! Complies with A006 §9: Explicit Domain-to-Storage Mapping Architecture.

use chrono::{DateTime, Utc};
use relay_domain::{
    ActionHash, ActionId, Digest, DsseEnvelope, LedgerEntry, ReceiptId, SequenceNumber, SessionId,
};
use serde::{Deserialize, Serialize};

/// Node identity record stored in `node_identity`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentityRecord {
    pub node_id: String,
    pub public_key_hex: String,
    pub key_algorithm: String,
    pub initialized_at: String,
    pub metadata_json: String,
}

/// Cedar policy snapshot record stored in `policy_snapshots`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshotRecord {
    pub policy_hash: String,
    pub cedar_bundle: String,
    pub created_at_utc: String,
}

/// Human operator approval record stored in `approvals`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub receipt_id: String,
    pub nonce: String,
    pub approver_id: String,
    pub channel: String,
    pub decision: String,
    pub decided_at_utc: String,
    pub metadata_json: String,
}

/// Raw database row representing a joined ledger entry and receipt
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    pub sequence_number: u64,
    pub receipt_id: String,
    pub timestamp_utc: String,
    pub parent_hash: String,
    pub payload_hash: String,
    pub entry_hash: String,
    pub tool_namespace: String,
    pub tool_name: String,
    pub decision: String,
    pub status: String,
    pub policy_hash: String,
    pub dsse_envelope: Vec<u8>,
}

impl LedgerRow {
    /// Converts the storage row into a domain `LedgerEntry`
    pub fn to_domain_ledger_entry(&self) -> Result<LedgerEntry, relay_domain::LedgerError> {
        let seq = SequenceNumber(self.sequence_number);
        let receipt_id = self.receipt_id.parse::<ReceiptId>().map_err(|e| {
            relay_domain::LedgerError::Corruption(format!("Invalid receipt_id UUID in DB: {e}"))
        })?;

        let prev_receipt_hash = Digest::from_hex(&self.parent_hash).map_err(|e| {
            relay_domain::LedgerError::Corruption(format!("Invalid parent_hash hex in DB: {e}"))
        })?;

        let entry_hash = Digest::from_hex(&self.entry_hash).map_err(|e| {
            relay_domain::LedgerError::Corruption(format!("Invalid entry_hash hex in DB: {e}"))
        })?;

        let payload_hash = Digest::from_hex(&self.payload_hash).map_err(|e| {
            relay_domain::LedgerError::Corruption(format!("Invalid payload_hash hex in DB: {e}"))
        })?;

        let recorded_at = DateTime::parse_from_rfc3339(&self.timestamp_utc)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        // Parse DSSE envelope or reconstruct dummy for genesis
        let (envelope, session_id, action_id, action_hash) = if self.sequence_number == 0 {
            // Genesis entry
            let dummy_env = DsseEnvelope {
                payload_type: "application/vnd.relay.genesis+json".to_string(),
                payload: hex::encode(&self.dsse_envelope),
                signatures: Vec::new(),
            };
            (
                dummy_env,
                SessionId::from_uuid(uuid::Uuid::nil()),
                ActionId::from_uuid(uuid::Uuid::nil()),
                ActionHash::compute(&self.dsse_envelope),
            )
        } else {
            let env: DsseEnvelope = serde_json::from_slice(&self.dsse_envelope).map_err(|e| {
                relay_domain::LedgerError::Corruption(format!(
                    "Failed to deserialize dsse_envelope JSON: {e}"
                ))
            })?;

            // Try to extract session_id and action_id from envelope statement payload
            let (sess, act, act_hash) = match relay_receipts::base64_decode(&env.payload) {
                Ok(statement_bytes) => {
                    if let Ok(stmt) =
                        serde_json::from_slice::<relay_domain::InTotoStatement>(&statement_bytes)
                    {
                        (
                            stmt.predicate.session_id,
                            stmt.predicate.action_id,
                            stmt.predicate.action_hash,
                        )
                    } else {
                        (
                            SessionId::from_uuid(uuid::Uuid::nil()),
                            ActionId::from_uuid(uuid::Uuid::nil()),
                            ActionHash::compute(&statement_bytes),
                        )
                    }
                }
                Err(_) => (
                    SessionId::from_uuid(uuid::Uuid::nil()),
                    ActionId::from_uuid(uuid::Uuid::nil()),
                    ActionHash::compute(b""),
                ),
            };

            (env, sess, act, act_hash)
        };

        Ok(LedgerEntry {
            sequence_number: seq,
            session_id,
            action_id,
            action_hash,
            receipt_id,
            receipt_hash: payload_hash,
            previous_receipt_hash: prev_receipt_hash,
            entry_hash,
            dsse_envelope: envelope,
            recorded_at,
        })
    }
}
