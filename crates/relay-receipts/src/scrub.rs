//! Secret scrubbing and leak prevention guard for Action Receipts.

use crate::error::ReceiptError;

/// Patterns that indicate sensitive credentials that must never enter a receipt.
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "sk-proj-",
    "AKIA",
    "ASIA",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
];

/// Defensively inspects serialized receipt JSON bytes for prohibited secret strings.
pub fn scrub_payload(payload: &[u8]) -> Result<(), ReceiptError> {
    let payload_str = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            return Err(ReceiptError::ProhibitedSecretDetected(
                "Receipt payload contains non-UTF-8 bytes".to_string(),
            ));
        }
    };

    // Check for sensitive prefixes and substrings
    for &pattern in FORBIDDEN_SUBSTRINGS {
        if payload_str.contains(pattern) {
            return Err(ReceiptError::ProhibitedSecretDetected(format!(
                "Receipt payload contains forbidden secret pattern: '{pattern}'"
            )));
        }
    }

    // Check for raw authorization headers
    if payload_str.to_lowercase().contains("authorization: bearer") {
        return Err(ReceiptError::ProhibitedSecretDetected(
            "Receipt payload contains raw 'Authorization: Bearer' header".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrubber_allows_clean_payload() {
        let clean = b"{\"action\":\"github.read\",\"resource\":\"github://github.com/org/repo\"}";
        assert!(scrub_payload(clean).is_ok());
    }

    #[test]
    fn test_scrubber_detects_github_pat() {
        let dirty = b"{\"token\":\"ghp_secret_token_1234567890\"}";
        assert!(scrub_payload(dirty).is_err());
    }

    #[test]
    fn test_scrubber_detects_auth_header() {
        let dirty = b"{\"headers\":\"Authorization: Bearer xyz123\"}";
        assert!(scrub_payload(dirty).is_err());
    }

    #[test]
    fn test_scrubber_detects_private_key() {
        let dirty = b"{\"key\":\"-----BEGIN RSA PRIVATE KEY-----\"}";
        assert!(scrub_payload(dirty).is_err());
    }
}
