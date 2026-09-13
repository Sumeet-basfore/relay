//! RFC 8785 JSON Canonicalization Scheme (JCS) serializer for in-toto statements.

use crate::error::ReceiptError;
use relay_domain::InTotoStatement;

/// Serializes an in-toto Statement into deterministic RFC 8785 canonical JSON bytes.
pub fn canonicalize_statement(statement: &InTotoStatement) -> Result<Vec<u8>, ReceiptError> {
    serde_jcs::to_vec(statement)
        .map_err(|e| ReceiptError::CanonicalizationFailed(format!("JCS serialization failed: {e}")))
}

/// Serializes any serde-serializable value into deterministic RFC 8785 canonical JSON bytes.
pub fn canonicalize_value<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, ReceiptError> {
    serde_jcs::to_vec(val)
        .map_err(|e| ReceiptError::CanonicalizationFailed(format!("JCS serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use relay_domain::{
        ActionHash, ActionId, ActionReceiptPredicate, InTotoSubject, ReceiptId, SessionId,
    };
    use serde_json::json;

    fn dummy_statement(arg1: &str, arg2: &str) -> InTotoStatement {
        let subject = vec![InTotoSubject::new("test_res", "sha256:abc")];
        let predicate = ActionReceiptPredicate {
            receipt_id: ReceiptId::new_v7(),
            action_id: ActionId::new_v7(),
            session_id: SessionId::new_v7(),
            action_hash: ActionHash::compute(b"dummy"),
            timestamp: Utc::now(),
            canonical_proposal: json!({ "z_key": arg2, "a_key": arg1 }),
            policy_decision: json!({ "decision": "ALLOW" }),
            approval: None,
            credential_lease: None,
            execution: json!({ "route": "native" }),
            observation: json!({ "status": "SUCCESS" }),
            epistemology: json!({ "asserted": ["auth"] }),
            parent_receipt_hash: None,
        };
        InTotoStatement::new(subject, predicate)
    }

    #[test]
    fn test_jcs_determinism_key_sorting() {
        let stmt1 = dummy_statement("val1", "val2");
        let bytes1 = canonicalize_statement(&stmt1).unwrap();
        let bytes2 = canonicalize_statement(&stmt1).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "Identical statements must produce identical bytes"
        );

        // Verify JSON string has keys sorted alphabetically: "a_key" before "z_key"
        let json_str = String::from_utf8(bytes1).unwrap();
        let idx_a = json_str.find("\"a_key\"").unwrap();
        let idx_z = json_str.find("\"z_key\"").unwrap();
        assert!(
            idx_a < idx_z,
            "Keys must be lexicographically sorted by JCS"
        );
    }
}
