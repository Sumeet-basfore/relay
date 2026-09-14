//! Ed25519 DSSE Receipt Signer implementation.

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::fmt;

use crate::canonical::canonicalize_statement;
use crate::dsse::{base64_encode, compute_pae, create_envelope};
use crate::error::ReceiptError;
use relay_domain::{CryptoError, DsseEnvelope, DsseSignature, InTotoStatement, ReceiptSigner};

/// Ed25519 cryptographic receipt signer for DSSE envelopes.
pub struct Ed25519ReceiptSigner {
    key_id: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519ReceiptSigner {
    /// Generates a new Ed25519 signing keypair with a custom or default key ID.
    pub fn generate(key_id: impl Into<String>) -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Self {
            key_id: key_id.into(),
            signing_key,
            verifying_key,
        }
    }

    /// Initializes a signer from raw 32-byte secret seed bytes.
    pub fn from_bytes(bytes: &[u8; 32], key_id: impl Into<String>) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            key_id: key_id.into(),
            signing_key,
            verifying_key,
        }
    }

    /// Initializes a signer from a 64-character hexadecimal seed string.
    pub fn from_hex(hex_str: &str, key_id: impl Into<String>) -> Result<Self, ReceiptError> {
        let clean = hex_str.trim();
        let raw = hex::decode(clean).map_err(|e| {
            ReceiptError::Crypto(format!("Invalid hex string for signing key: {e}"))
        })?;
        if raw.len() != 32 {
            return Err(ReceiptError::Crypto(format!(
                "Key hex decoded to {} bytes, expected 32",
                raw.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Ok(Self::from_bytes(&arr, key_id))
    }

    /// Loads a signing key from a file (raw 32 bytes or 64 hex characters).
    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
        key_id: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        let path_ref = path.as_ref();
        let bytes = std::fs::read(path_ref).map_err(|e| {
            ReceiptError::Crypto(format!(
                "Failed to read key file '{}': {e}",
                path_ref.display()
            ))
        })?;

        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Self::from_bytes(&arr, key_id))
        } else if let Ok(s) = std::str::from_utf8(&bytes) {
            Self::from_hex(s.trim(), key_id)
        } else {
            Err(ReceiptError::Crypto(
                "Key file must contain exactly 32 raw bytes or 64 hex characters".to_string(),
            ))
        }
    }

    /// Saves the private signing key seed bytes to a file with restrictive permissions (0600 on Unix).
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), ReceiptError> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ReceiptError::Crypto(format!("Failed to create key directory: {e}"))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(parent) {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o700);
                        let _ = std::fs::set_permissions(parent, perms);
                    }
                }
            }
        }

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut file = opts.open(path_ref).map_err(|e| {
            ReceiptError::Crypto(format!(
                "Failed to create key file '{}': {e}",
                path_ref.display()
            ))
        })?;

        use std::io::Write;
        file.write_all(self.signing_key.as_bytes())
            .map_err(|e| ReceiptError::Crypto(format!("Failed to write key material: {e}")))?;

        Ok(())
    }

    /// Returns the active `VerifyingKey`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Pure synchronous signing of an in-toto Statement producing a DSSE envelope.
    pub fn sign_statement_sync(
        &self,
        statement: &InTotoStatement,
    ) -> Result<DsseEnvelope, ReceiptError> {
        let canonical_bytes = canonicalize_statement(statement)?;
        self.sign_payload_bytes_sync(DsseEnvelope::PAYLOAD_TYPE, &canonical_bytes)
    }

    /// Pure synchronous signing of raw payload bytes into a DSSE envelope.
    pub fn sign_payload_bytes_sync(
        &self,
        payload_type: &str,
        payload_bytes: &[u8],
    ) -> Result<DsseEnvelope, ReceiptError> {
        let pae = compute_pae(payload_type, payload_bytes);
        let signature = self.signing_key.sign(&pae);
        let signature_base64 = base64_encode(&signature.to_bytes());

        let sig_block = DsseSignature {
            keyid: self.key_id.clone(),
            sig: signature_base64,
        };

        Ok(create_envelope(
            payload_type,
            payload_bytes,
            vec![sig_block],
        ))
    }
}

impl Default for Ed25519ReceiptSigner {
    fn default() -> Self {
        Self::generate("relay-local-ed25519-v1")
    }
}

impl fmt::Debug for Ed25519ReceiptSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519ReceiptSigner")
            .field("key_id", &self.key_id)
            .field(
                "public_key_hex",
                &hex::encode(self.verifying_key.to_bytes()),
            )
            .field("signing_key", &"[REDACTED SECRET KEY]")
            .finish()
    }
}

#[async_trait]
impl ReceiptSigner for Ed25519ReceiptSigner {
    async fn sign_statement(
        &self,
        statement: &InTotoStatement,
    ) -> Result<DsseEnvelope, CryptoError> {
        self.sign_statement_sync(statement)
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn export_public_key(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use relay_domain::{
        ActionHash, ActionId, ActionReceiptPredicate, InTotoSubject, ReceiptId, SessionId,
    };
    use serde_json::json;

    fn sample_statement() -> InTotoStatement {
        let subject = vec![InTotoSubject::new("test_res", "sha256:abc")];
        let predicate = ActionReceiptPredicate {
            receipt_id: ReceiptId::new_v7(),
            action_id: ActionId::new_v7(),
            session_id: SessionId::new_v7(),
            action_hash: ActionHash::compute(b"hash"),
            timestamp: Utc::now(),
            canonical_proposal: json!({ "tool": "test" }),
            policy_decision: json!({ "decision": "ALLOW" }),
            approval: None,
            credential_lease: None,
            execution: json!({ "status": "SUCCESS" }),
            observation: json!({ "exit_code": 0 }),
            epistemology: json!({ "asserted": ["auth"] }),
            parent_receipt_hash: None,
        };
        InTotoStatement::new(subject, predicate)
    }

    #[test]
    fn test_signer_generates_valid_envelope() {
        let signer = Ed25519ReceiptSigner::default();
        let stmt = sample_statement();
        let env = signer.sign_statement_sync(&stmt).unwrap();

        assert_eq!(env.payload_type, DsseEnvelope::PAYLOAD_TYPE);
        assert!(!env.payload.is_empty());
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(env.signatures[0].keyid, "relay-local-ed25519-v1");
        assert!(!env.signatures[0].sig.is_empty());
    }

    #[test]
    fn test_signer_never_leaks_private_key_in_debug() {
        let signer = Ed25519ReceiptSigner::default();
        let debug_str = format!("{signer:?}");
        assert!(debug_str.contains("[REDACTED SECRET KEY]"));
        assert!(!debug_str.contains("secret"));
    }
}
