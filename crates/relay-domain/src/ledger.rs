use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{ActionHash, ActionId, Digest, ReceiptId, SequenceNumber, SessionId};
use crate::receipt::DsseEnvelope;

/// A single append-only hash-chained storage node in the SQLite ledger
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub sequence_number: SequenceNumber,
    pub session_id: SessionId,
    pub action_id: ActionId,
    pub action_hash: ActionHash,
    pub receipt_id: ReceiptId,
    pub receipt_hash: Digest,
    pub previous_receipt_hash: Digest,
    pub entry_hash: Digest,
    pub dsse_envelope: DsseEnvelope,
    pub recorded_at: DateTime<Utc>,
}

impl LedgerEntry {
    /// Computes the canonical cryptographic EntryHash binding sequence, parent hash, and payload hash (A006 §5.1)
    /// H_n = SHA-256(BE_U64(n) || Bytes(ParentHash_{n-1}) || Bytes(PayloadHash_n))
    pub fn compute_entry_hash(
        sequence_number: SequenceNumber,
        parent_hash: &Digest,
        payload_hash: &Digest,
    ) -> Digest {
        let mut bytes = Vec::with_capacity(8 + 32 + 32);
        bytes.extend_from_slice(&sequence_number.as_u64().to_be_bytes());
        bytes.extend_from_slice(parent_hash.as_bytes());
        bytes.extend_from_slice(payload_hash.as_bytes());
        Digest::compute(&bytes)
    }

    /// Accessor for the parent hash
    pub fn parent_hash(&self) -> &Digest {
        &self.previous_receipt_hash
    }

    /// Accessor for the payload hash
    pub fn payload_hash(&self) -> &Digest {
        &self.receipt_hash
    }
}
