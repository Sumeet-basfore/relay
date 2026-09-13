//! Independent forensic verification engine for Relay SQLite Ledgers.
//!
//! Complies with A006 §7: Systematic Verification Algorithm.
//! Capable of verifying offline SQLite ledger files without active daemon execution.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use relay_domain::{Digest, DsseEnvelope, InTotoStatement, LedgerError};
use relay_receipts::ReceiptVerifier;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::hash_chain::{
    compute_entry_hash, compute_payload_hash, GENESIS_PARENT_HASH_HEX, GENESIS_SEQUENCE,
};

/// Status of the ledger verification operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerVerificationStatus {
    /// The entire ledger from genesis to head is cryptographically valid
    Valid,
    /// The ledger contains zero entries
    EmptyLedger,
    /// A sequence number gap was detected
    SequenceGap { expected: u64, actual: u64 },
    /// Parent hash does not match previous entry's entry_hash
    BrokenChain {
        sequence_number: u64,
        expected_parent: String,
        actual_parent: String,
    },
    /// The SHA-256 payload hash does not match the canonical DSSE bytes
    PayloadHashMismatch {
        sequence_number: u64,
        expected: String,
        computed: String,
    },
    /// The entry hash does not match SHA-256(BE_U64(seq) || parent || payload)
    EntryHashMismatch {
        sequence_number: u64,
        expected: String,
        computed: String,
    },
    /// Digital signature or in-toto statement validation failed
    InvalidSignature {
        sequence_number: u64,
        receipt_id: String,
        reason: String,
    },
    /// Database table or row is unreadable / corrupted
    CorruptedDatabase(String),
}

impl LedgerVerificationStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Structured forensic report generated after ledger verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerVerificationReport {
    pub total_verified_entries: u64,
    pub head_sequence: u64,
    pub head_hash: String,
    pub genesis_hash: String,
    pub status: LedgerVerificationStatus,
    pub verified_at: DateTime<Utc>,
    pub duration_ms: u64,
}

/// Offline and online verifier for Relay SQLite ledgers
pub struct LedgerVerifier;

impl LedgerVerifier {
    /// Verifies a ledger file from disk given its file path
    pub fn verify_file(
        path: impl AsRef<Path>,
        public_key: Option<&[u8; 32]>,
        from_seq: Option<u64>,
    ) -> Result<LedgerVerificationReport, LedgerError> {
        let conn = Connection::open_with_flags(
            path.as_ref(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| LedgerError::ConnectionFailed(format!("Failed to open ledger file: {e}")))?;

        Self::verify_connection(&conn, public_key, from_seq)
    }

    /// Verifies a ledger given an open rusqlite Connection
    pub fn verify_connection(
        conn: &Connection,
        public_key: Option<&[u8; 32]>,
        from_seq: Option<u64>,
    ) -> Result<LedgerVerificationReport, LedgerError> {
        let start_time = std::time::Instant::now();
        let start_seq = from_seq.unwrap_or(GENESIS_SEQUENCE);

        // Optional ReceiptVerifier
        let receipt_verifier = match public_key {
            Some(bytes) => match VerifyingKey::from_bytes(bytes) {
                Ok(vk) => Some(ReceiptVerifier::new(vk)),
                Err(e) => {
                    return Err(LedgerError::Corruption(format!(
                        "Invalid Ed25519 public key bytes: {e}"
                    )));
                }
            },
            None => {
                // If public key is not provided, try to read it from node_identity
                let key_query: Result<String, _> = conn.query_row(
                    "SELECT public_key_hex FROM node_identity LIMIT 1",
                    [],
                    |row| row.get(0),
                );
                if let Ok(key_hex) = key_query {
                    if let Ok(bytes) = hex::decode(&key_hex) {
                        if let Ok(arr) = bytes.as_slice().try_into() {
                            VerifyingKey::from_bytes(arr).ok().map(ReceiptVerifier::new)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        // Prepare query streaming rows sequentially
        let mut stmt = conn
            .prepare(
                "SELECT l.sequence_number, l.parent_hash, l.payload_hash, l.entry_hash, r.dsse_envelope, l.receipt_id
                 FROM ledger_entries l
                 JOIN receipts r ON l.receipt_id = r.receipt_id
                 WHERE l.sequence_number >= ?1
                 ORDER BY l.sequence_number ASC",
            )
            .map_err(|e| LedgerError::QueryError(format!("Prepare verification query failed: {e}")))?;

        let mut expected_sequence: u64 = start_seq;
        let mut expected_parent_hash = if start_seq == 0 {
            GENESIS_PARENT_HASH_HEX.to_string()
        } else {
            // Read parent hash for start_seq
            let prev_hash: Result<String, _> = conn.query_row(
                "SELECT entry_hash FROM ledger_entries WHERE sequence_number = ?1",
                rusqlite::params![start_seq - 1],
                |row| row.get(0),
            );
            match prev_hash {
                Ok(h) => h,
                Err(_) => {
                    return Ok(LedgerVerificationReport {
                        total_verified_entries: 0,
                        head_sequence: 0,
                        head_hash: String::new(),
                        genesis_hash: String::new(),
                        status: LedgerVerificationStatus::BrokenChain {
                            sequence_number: start_seq,
                            expected_parent: "previous block entry_hash".to_string(),
                            actual_parent: "unknown".to_string(),
                        },
                        verified_at: Utc::now(),
                        duration_ms: start_time.elapsed().as_millis() as u64,
                    });
                }
            }
        };

        let mut rows = stmt.query(rusqlite::params![start_seq]).map_err(|e| {
            LedgerError::QueryError(format!("Execute verification query failed: {e}"))
        })?;

        let mut count: u64 = 0;
        let mut head_seq: u64 = 0;
        let mut head_hash = String::new();
        let mut genesis_hash = String::new();

        while let Some(row) = rows
            .next()
            .map_err(|e| LedgerError::Corruption(format!("Failed to read ledger row: {e}")))?
        {
            let seq: u64 = row
                .get(0)
                .map_err(|e| LedgerError::Corruption(format!("Invalid sequence_number: {e}")))?;
            let parent_hash: String = row
                .get(1)
                .map_err(|e| LedgerError::Corruption(format!("Invalid parent_hash: {e}")))?;
            let payload_hash: String = row
                .get(2)
                .map_err(|e| LedgerError::Corruption(format!("Invalid payload_hash: {e}")))?;
            let entry_hash: String = row
                .get(3)
                .map_err(|e| LedgerError::Corruption(format!("Invalid entry_hash: {e}")))?;
            let dsse_bytes: Vec<u8> = row
                .get(4)
                .map_err(|e| LedgerError::Corruption(format!("Invalid dsse_envelope blob: {e}")))?;
            let receipt_id_str: String = row
                .get(5)
                .map_err(|e| LedgerError::Corruption(format!("Invalid receipt_id: {e}")))?;

            if seq == 0 {
                genesis_hash = entry_hash.clone();
            }

            // 1. Sequence monotonicity check
            if seq != expected_sequence {
                return Ok(LedgerVerificationReport {
                    total_verified_entries: count,
                    head_sequence: head_seq,
                    head_hash,
                    genesis_hash,
                    status: LedgerVerificationStatus::SequenceGap {
                        expected: expected_sequence,
                        actual: seq,
                    },
                    verified_at: Utc::now(),
                    duration_ms: start_time.elapsed().as_millis() as u64,
                });
            }

            // 2. Parent hash linkage check
            if parent_hash != expected_parent_hash {
                return Ok(LedgerVerificationReport {
                    total_verified_entries: count,
                    head_sequence: head_seq,
                    head_hash,
                    genesis_hash,
                    status: LedgerVerificationStatus::BrokenChain {
                        sequence_number: seq,
                        expected_parent: expected_parent_hash,
                        actual_parent: parent_hash,
                    },
                    verified_at: Utc::now(),
                    duration_ms: start_time.elapsed().as_millis() as u64,
                });
            }

            // 3. Payload hash check
            let computed_payload_hash = compute_payload_hash(&dsse_bytes);
            if computed_payload_hash.to_hex() != payload_hash {
                return Ok(LedgerVerificationReport {
                    total_verified_entries: count,
                    head_sequence: head_seq,
                    head_hash,
                    genesis_hash,
                    status: LedgerVerificationStatus::PayloadHashMismatch {
                        sequence_number: seq,
                        expected: payload_hash,
                        computed: computed_payload_hash.to_hex(),
                    },
                    verified_at: Utc::now(),
                    duration_ms: start_time.elapsed().as_millis() as u64,
                });
            }

            // 4. Entry hash formulation check
            let parent_digest = Digest::from_hex(&parent_hash).map_err(|e| {
                LedgerError::Corruption(format!(
                    "Failed to parse parent_hash hex '{parent_hash}': {e}"
                ))
            })?;
            let computed_entry_hash =
                compute_entry_hash(seq, &parent_digest, &computed_payload_hash);
            if computed_entry_hash.to_hex() != entry_hash {
                return Ok(LedgerVerificationReport {
                    total_verified_entries: count,
                    head_sequence: head_seq,
                    head_hash,
                    genesis_hash,
                    status: LedgerVerificationStatus::EntryHashMismatch {
                        sequence_number: seq,
                        expected: entry_hash,
                        computed: computed_entry_hash.to_hex(),
                    },
                    verified_at: Utc::now(),
                    duration_ms: start_time.elapsed().as_millis() as u64,
                });
            }

            // 5. Cryptographic signature and in-toto statement verification (seq >= 1)
            if seq > 0 {
                if let Some(ref verifier) = receipt_verifier {
                    let envelope: DsseEnvelope = match serde_json::from_slice(&dsse_bytes) {
                        Ok(env) => env,
                        Err(e) => {
                            return Ok(LedgerVerificationReport {
                                total_verified_entries: count,
                                head_sequence: head_seq,
                                head_hash,
                                genesis_hash,
                                status: LedgerVerificationStatus::InvalidSignature {
                                    sequence_number: seq,
                                    receipt_id: receipt_id_str,
                                    reason: format!("Failed to parse DSSE envelope JSON: {e}"),
                                },
                                verified_at: Utc::now(),
                                duration_ms: start_time.elapsed().as_millis() as u64,
                            });
                        }
                    };

                    match verifier.verify_envelope(&envelope) {
                        Ok((statement_bytes, _key_id)) => {
                            // Check in-toto statement parsing
                            match serde_json::from_slice::<InTotoStatement>(&statement_bytes) {
                                Ok(stmt) => {
                                    if stmt.predicate.receipt_id.to_string() != receipt_id_str {
                                        return Ok(LedgerVerificationReport {
                                            total_verified_entries: count,
                                            head_sequence: head_seq,
                                            head_hash,
                                            genesis_hash,
                                            status: LedgerVerificationStatus::InvalidSignature {
                                                sequence_number: seq,
                                                receipt_id: receipt_id_str.clone(),
                                                reason: format!(
                                                    "Statement receipt_id '{}' does not match ledger receipt_id '{}'",
                                                    stmt.predicate.receipt_id, receipt_id_str
                                                ),
                                            },
                                            verified_at: Utc::now(),
                                            duration_ms: start_time.elapsed().as_millis() as u64,
                                        });
                                    }
                                }
                                Err(e) => {
                                    return Ok(LedgerVerificationReport {
                                        total_verified_entries: count,
                                        head_sequence: head_seq,
                                        head_hash,
                                        genesis_hash,
                                        status: LedgerVerificationStatus::InvalidSignature {
                                            sequence_number: seq,
                                            receipt_id: receipt_id_str,
                                            reason: format!(
                                                "Failed to parse in-toto statement: {e}"
                                            ),
                                        },
                                        verified_at: Utc::now(),
                                        duration_ms: start_time.elapsed().as_millis() as u64,
                                    });
                                }
                            }
                        }
                        Err(fail) => {
                            return Ok(LedgerVerificationReport {
                                total_verified_entries: count,
                                head_sequence: head_seq,
                                head_hash,
                                genesis_hash,
                                status: LedgerVerificationStatus::InvalidSignature {
                                    sequence_number: seq,
                                    receipt_id: receipt_id_str,
                                    reason: format!("DSSE signature verification failed: {fail:?}"),
                                },
                                verified_at: Utc::now(),
                                duration_ms: start_time.elapsed().as_millis() as u64,
                            });
                        }
                    }
                }
            }

            expected_parent_hash = entry_hash.clone();
            expected_sequence += 1;
            head_seq = seq;
            head_hash = entry_hash;
            count += 1;
        }

        if count == 0 {
            return Ok(LedgerVerificationReport {
                total_verified_entries: 0,
                head_sequence: 0,
                head_hash: String::new(),
                genesis_hash: String::new(),
                status: LedgerVerificationStatus::EmptyLedger,
                verified_at: Utc::now(),
                duration_ms: start_time.elapsed().as_millis() as u64,
            });
        }

        Ok(LedgerVerificationReport {
            total_verified_entries: count,
            head_sequence: head_seq,
            head_hash,
            genesis_hash,
            status: LedgerVerificationStatus::Valid,
            verified_at: Utc::now(),
            duration_ms: start_time.elapsed().as_millis() as u64,
        })
    }
}
