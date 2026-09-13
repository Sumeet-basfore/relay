//! Dead Simple Signing Envelope (DSSE - RFC 9598) encoding and formatting.

use crate::error::ReceiptError;
use base64::prelude::*;
use relay_domain::{DsseEnvelope, DsseSignature};

/// Computes the RFC 9598 Pre-Authentication Encoding (PAE) for DSSE signing.
///
/// Format:
/// ```text
/// PAE(type, body) = "DSSEv1" + SP +
///                   ASCII(len(type)) + SP +
///                   type + SP +
///                   ASCII(len(body)) + SP +
///                   body
/// ```
pub fn compute_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let type_len_str = type_bytes.len().to_string();
    let payload_len_str = payload.len().to_string();

    let mut pae = Vec::with_capacity(
        6 + 1
            + type_len_str.len()
            + 1
            + type_bytes.len()
            + 1
            + payload_len_str.len()
            + 1
            + payload.len(),
    );
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(type_len_str.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(type_bytes);
    pae.push(b' ');
    pae.extend_from_slice(payload_len_str.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

/// Base64 encodes payload bytes into standard Base64 string.
pub fn base64_encode(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Base64 decodes standard Base64 string into bytes.
pub fn base64_decode(data: &str) -> Result<Vec<u8>, ReceiptError> {
    BASE64_STANDARD
        .decode(data)
        .map_err(|e| ReceiptError::CorruptedEnvelope(format!("Base64 decoding failed: {e}")))
}

/// Creates a `DsseEnvelope` from raw payload bytes and digital signatures.
pub fn create_envelope(
    payload_type: impl Into<String>,
    payload_bytes: &[u8],
    signatures: Vec<DsseSignature>,
) -> DsseEnvelope {
    let b64_payload = base64_encode(payload_bytes);
    DsseEnvelope {
        payload_type: payload_type.into(),
        payload: b64_payload,
        signatures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pae_computation_rfc9598() {
        let payload_type = "application/vnd.in-toto+json";
        let body = b"{\"hello\":\"world\"}";
        let pae = compute_pae(payload_type, body);

        let expected_prefix = format!(
            "DSSEv1 {} {} {} ",
            payload_type.len(),
            payload_type,
            body.len()
        );
        assert!(pae.starts_with(expected_prefix.as_bytes()));
        assert_eq!(&pae[expected_prefix.len()..], body);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Relay DSSE cryptographic payload test string 12345!@#";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(original, decoded.as_slice());
    }
}
