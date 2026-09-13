//! Independent receipt verification engine.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use relay_domain::{ActionHash, ActionReceipt, Digest, DsseEnvelope, InTotoStatement, ReceiptId};

use crate::dsse::{base64_decode, compute_pae};

/// The outcome of an independent receipt verification operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Receipt is cryptographically valid and all domain bindings match.
    Valid {
        receipt_id: ReceiptId,
        action_hash: ActionHash,
        key_id: String,
        statement: Box<InTotoStatement>,
    },
    /// The Ed25519 digital signature does not match the payload.
    InvalidSignature { key_id: String, reason: String },
    /// The DSSE payload or envelope is structurally malformed or corrupted.
    CorruptedPayload(String),
    /// The envelope or statement uses an unknown schema or version.
    UnsupportedSchema(String),
    /// The signed payload content diverges from expected domain invariants.
    DomainIntegrityFailure(String),
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// Independent validator for Relay Action Receipts.
pub struct ReceiptVerifier {
    verifying_key: VerifyingKey,
    key_id: Option<String>,
}

impl ReceiptVerifier {
    /// Creates a verifier using an Ed25519 `VerifyingKey`.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self {
            verifying_key,
            key_id: None,
        }
    }

    /// Creates a verifier bound to an explicit key ID and public key bytes.
    pub fn from_public_key_bytes(
        key_id: impl Into<String>,
        bytes: &[u8; 32],
    ) -> Result<Self, String> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| format!("Invalid Ed25519 public key bytes: {e}"))?;
        Ok(Self {
            verifying_key,
            key_id: Some(key_id.into()),
        })
    }

    /// Verifies a complete signed `ActionReceipt` against optional expected domain invariants.
    pub fn verify_receipt(
        &self,
        receipt: &ActionReceipt,
        expected_action_hash: Option<&ActionHash>,
        expected_policy_digest: Option<&Digest>,
    ) -> VerificationResult {
        // 1. Verify the underlying DSSE envelope
        let (statement_bytes, key_id) = match self.verify_envelope(&receipt.dsse_envelope) {
            Ok(res) => res,
            Err(failure) => return failure,
        };

        // 2. Validate receipt_hash matches canonical statement hash
        let computed_receipt_hash = Digest::compute(&statement_bytes);
        if computed_receipt_hash != receipt.receipt_hash {
            return VerificationResult::DomainIntegrityFailure(format!(
                "ReceiptHash mismatch: envelope hash '{}' != computed hash '{}'",
                receipt.receipt_hash.to_hex(),
                computed_receipt_hash.to_hex()
            ));
        }

        // 3. Deserialize in-toto Statement
        let statement: InTotoStatement = match serde_json::from_slice(&statement_bytes) {
            Ok(s) => s,
            Err(e) => {
                return VerificationResult::CorruptedPayload(format!(
                    "Failed to parse in-toto statement: {e}"
                ))
            }
        };

        // 4. Schema verification
        if statement.statement_type != InTotoStatement::STATEMENT_TYPE {
            return VerificationResult::UnsupportedSchema(format!(
                "Unsupported statement type '{}', expected '{}'",
                statement.statement_type,
                InTotoStatement::STATEMENT_TYPE
            ));
        }
        if statement.predicate_type != InTotoStatement::PREDICATE_TYPE {
            return VerificationResult::UnsupportedSchema(format!(
                "Unsupported predicate type '{}', expected '{}'",
                statement.predicate_type,
                InTotoStatement::PREDICATE_TYPE
            ));
        }

        // 5. Domain integrity checks
        if statement.predicate.receipt_id != receipt.receipt_id {
            return VerificationResult::DomainIntegrityFailure(format!(
                "ReceiptId mismatch: receipt '{}' != statement '{}'",
                receipt.receipt_id, statement.predicate.receipt_id
            ));
        }

        if statement.predicate.action_id != receipt.action_id {
            return VerificationResult::DomainIntegrityFailure(format!(
                "ActionId mismatch: receipt '{}' != statement '{}'",
                receipt.action_id, statement.predicate.action_id
            ));
        }

        if statement.predicate.action_hash != receipt.action_hash {
            return VerificationResult::DomainIntegrityFailure(format!(
                "ActionHash mismatch: receipt '{}' != statement '{}'",
                receipt.action_hash.to_hex(),
                statement.predicate.action_hash.to_hex()
            ));
        }

        if let Some(expected_hash) = expected_action_hash {
            if &receipt.action_hash != expected_hash {
                return VerificationResult::DomainIntegrityFailure(format!(
                    "ActionHash mismatch against expected: receipt '{}' != expected '{}'",
                    receipt.action_hash.to_hex(),
                    expected_hash.to_hex()
                ));
            }
        }

        if let Some(expected_digest) = expected_policy_digest {
            let policy_digest_str = statement
                .predicate
                .policy_decision
                .get("policy_digest")
                .and_then(|v| v.as_str());
            if let Some(p_str) = policy_digest_str {
                if p_str != expected_digest.to_hex() {
                    return VerificationResult::DomainIntegrityFailure(format!(
                        "Policy digest mismatch: statement '{p_str}' != expected '{}'",
                        expected_digest.to_hex()
                    ));
                }
            }
        }

        VerificationResult::Valid {
            receipt_id: receipt.receipt_id,
            action_hash: receipt.action_hash,
            key_id,
            statement: Box::new(statement),
        }
    }

    /// Verifies a DSSE envelope's signature and extracts decoded canonical payload bytes.
    pub fn verify_envelope(
        &self,
        envelope: &DsseEnvelope,
    ) -> Result<(Vec<u8>, String), VerificationResult> {
        // 1. Schema check
        if envelope.payload_type != DsseEnvelope::PAYLOAD_TYPE {
            return Err(VerificationResult::UnsupportedSchema(format!(
                "Unsupported DSSE payloadType '{}', expected '{}'",
                envelope.payload_type,
                DsseEnvelope::PAYLOAD_TYPE
            )));
        }

        if envelope.signatures.is_empty() {
            return Err(VerificationResult::CorruptedPayload(
                "DSSE envelope contains zero signatures".to_string(),
            ));
        }

        // 2. Decode payload
        let payload_bytes = match base64_decode(&envelope.payload) {
            Ok(b) => b,
            Err(e) => return Err(VerificationResult::CorruptedPayload(e.to_string())),
        };

        // 3. Reconstruct PAE
        let pae = compute_pae(&envelope.payload_type, &payload_bytes);

        // 4. Find matching signature or verify first
        for sig_block in &envelope.signatures {
            if let Some(ref required_key_id) = self.key_id {
                if &sig_block.keyid != required_key_id {
                    continue;
                }
            }

            let sig_bytes = match base64_decode(&sig_block.sig) {
                Ok(b) => b,
                Err(e) => {
                    return Err(VerificationResult::CorruptedPayload(format!(
                        "Invalid signature base64: {e}"
                    )))
                }
            };

            let sig_array: [u8; 64] = match sig_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    return Err(VerificationResult::CorruptedPayload(
                        "Invalid signature length (must be 64 bytes)".to_string(),
                    ))
                }
            };

            let signature = Signature::from_bytes(&sig_array);

            match self.verifying_key.verify(&pae, &signature) {
                Ok(()) => return Ok((payload_bytes, sig_block.keyid.clone())),
                Err(e) => {
                    return Err(VerificationResult::InvalidSignature {
                        key_id: sig_block.keyid.clone(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        Err(VerificationResult::InvalidSignature {
            key_id: self.key_id.clone().unwrap_or_else(|| "unknown".to_string()),
            reason: "No signature matched or verified with the provided public key".to_string(),
        })
    }
}
