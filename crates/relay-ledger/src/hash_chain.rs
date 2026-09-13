//! Cryptographic hash chain calculation and validation routines.
//!
//! Complies with A006 §5.1 and §5.2:
//! - PayloadHash_n = SHA-256(CanonicalDSSEBytes_n)
//! - EntryHash_n = SHA-256(BE_U64(n) || Bytes(ParentHash_{n-1}) || Bytes(PayloadHash_n))
//! - Genesis: Seq=0, Parent=0^64, Payload=JCS({system, node_id, version})

use relay_domain::{Digest, LedgerError};
use serde_json::json;
use sha2::{Digest as _, Sha256};

pub const GENESIS_SEQUENCE: u64 = 0;
pub const GENESIS_PARENT_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Returns the 32-byte all-zero genesis parent hash
pub fn genesis_parent_hash() -> Digest {
    Digest::from_bytes([0u8; 32])
}

/// Computes the SHA-256 payload hash of canonical DSSE envelope bytes (A006 §5.1)
pub fn compute_payload_hash(canonical_bytes: &[u8]) -> Digest {
    Digest::compute(canonical_bytes)
}

/// Computes the EntryHash binding sequence number, parent hash, and payload hash (A006 §5.1)
/// H_n = SHA-256(BE_U64(n) || Bytes(ParentHash_{n-1}) || Bytes(PayloadHash_n))
pub fn compute_entry_hash(sequence: u64, parent_hash: &Digest, payload_hash: &Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(sequence.to_be_bytes());
    hasher.update(parent_hash.as_bytes());
    hasher.update(payload_hash.as_bytes());
    Digest::from_bytes(hasher.finalize().into())
}

/// Computes the EntryHash from hex-encoded strings with format validation
pub fn compute_entry_hash_from_hex(
    sequence: u64,
    parent_hash_hex: &str,
    payload_hash_hex: &str,
) -> Result<Digest, LedgerError> {
    let parent_bytes = hex::decode(parent_hash_hex).map_err(|e| {
        LedgerError::Corruption(format!("Invalid parent hash hex '{parent_hash_hex}': {e}"))
    })?;
    if parent_bytes.len() != 32 {
        return Err(LedgerError::Corruption(format!(
            "Parent hash length must be 32 bytes, got {}",
            parent_bytes.len()
        )));
    }

    let payload_bytes = hex::decode(payload_hash_hex).map_err(|e| {
        LedgerError::Corruption(format!(
            "Invalid payload hash hex '{payload_hash_hex}': {e}"
        ))
    })?;
    if payload_bytes.len() != 32 {
        return Err(LedgerError::Corruption(format!(
            "Payload hash length must be 32 bytes, got {}",
            payload_bytes.len()
        )));
    }

    let parent_arr: [u8; 32] = parent_bytes
        .try_into()
        .map_err(|_| LedgerError::Corruption("Parent hash length conversion failed".to_string()))?;
    let payload_arr: [u8; 32] = payload_bytes.try_into().map_err(|_| {
        LedgerError::Corruption("Payload hash length conversion failed".to_string())
    })?;

    Ok(compute_entry_hash(
        sequence,
        &Digest::from_bytes(parent_arr),
        &Digest::from_bytes(payload_arr),
    ))
}

/// Generates the canonical JCS payload for the Genesis block (A006 §5.2)
pub fn generate_genesis_payload(node_id: &str) -> Result<Vec<u8>, LedgerError> {
    let val = json!({
        "node_id": node_id,
        "system": "RELAY_GATEWAY_GENESIS",
        "version": "1.0.0"
    });
    serde_jcs::to_vec(&val).map_err(|e| {
        LedgerError::SerializationError(format!("Failed to canonicalize genesis payload: {e}"))
    })
}

/// Computes all cryptographic components of the Genesis block
pub fn compute_genesis_block(node_id: &str) -> Result<(Vec<u8>, Digest, Digest), LedgerError> {
    let payload_bytes = generate_genesis_payload(node_id)?;
    let payload_hash = compute_payload_hash(&payload_bytes);
    let parent_hash = genesis_parent_hash();
    let entry_hash = compute_entry_hash(GENESIS_SEQUENCE, &parent_hash, &payload_hash);
    Ok((payload_bytes, payload_hash, entry_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_computation() {
        let node_id = "01918a20-4321-7000-8000-000000000001";
        let (payload_bytes, payload_hash, entry_hash) = compute_genesis_block(node_id).unwrap();

        // Verify payload is deterministic JCS
        let expected_json = r#"{"node_id":"01918a20-4321-7000-8000-000000000001","system":"RELAY_GATEWAY_GENESIS","version":"1.0.0"}"#;
        assert_eq!(
            String::from_utf8(payload_bytes.clone()).unwrap(),
            expected_json
        );

        // Verify payload hash
        let expected_payload_hash = Digest::compute(payload_bytes.as_slice());
        assert_eq!(payload_hash, expected_payload_hash);

        // Verify entry hash calculation
        let parent = genesis_parent_hash();
        let expected_entry_hash = compute_entry_hash(0, &parent, &payload_hash);
        assert_eq!(entry_hash, expected_entry_hash);
    }

    #[test]
    fn test_entry_hash_sensitivity() {
        let parent = Digest::compute(b"prev_block");
        let payload1 = Digest::compute(b"receipt_1");
        let payload2 = Digest::compute(b"receipt_2");

        let h1 = compute_entry_hash(1, &parent, &payload1);
        let h2 = compute_entry_hash(1, &parent, &payload2);
        let h3 = compute_entry_hash(2, &parent, &payload1);

        assert_ne!(
            h1, h2,
            "Different payloads must yield different entry hashes"
        );
        assert_ne!(
            h1, h3,
            "Different sequence numbers must yield different entry hashes"
        );
    }
}
