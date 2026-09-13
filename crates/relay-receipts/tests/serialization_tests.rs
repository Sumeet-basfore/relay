mod common;

use common::*;
use relay_domain::{DsseEnvelope, InTotoStatement};
use relay_receipts::{
    base64_decode, canonicalize_statement, canonicalize_value, ActionReceiptBuilder,
};

#[test]
fn test_deterministic_jcs_serialization() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let builder = ActionReceiptBuilder::new(&action, &decision);

    let domain = builder.build_domain().unwrap();
    let statement = domain.to_in_toto_statement().unwrap();

    let bytes_1 = canonicalize_statement(&statement).expect("First canonicalization");
    let bytes_2 = canonicalize_statement(&statement).expect("Second canonicalization");

    assert_eq!(
        bytes_1, bytes_2,
        "RFC 8785 JCS serialization must be strictly deterministic"
    );
}

#[test]
fn test_rfc8785_lexicographical_key_sorting() {
    let raw_val = serde_json::json!({
        "zebra": 1,
        "apple": 2,
        "banana": {
            "yellow": true,
            "curved": true,
            "green": false
        },
        "middle": null
    });

    let canonical_bytes = canonicalize_value(&raw_val).unwrap();
    let canonical_str = String::from_utf8(canonical_bytes).unwrap();

    // In RFC 8785, keys at every level MUST be sorted lexicographically
    let expected = r#"{"apple":2,"banana":{"curved":true,"green":false,"yellow":true},"middle":null,"zebra":1}"#;
    assert_eq!(canonical_str, expected);
}

#[test]
fn test_rfc8785_whitespace_stripping() {
    let formatted = serde_json::json!({
        "key1": [1, 2, 3],
        "key2": "value"
    });

    let canonical_bytes = canonicalize_value(&formatted).unwrap();
    let canonical_str = String::from_utf8(canonical_bytes).unwrap();

    assert!(!canonical_str.contains(" "));
    assert!(!canonical_str.contains("\n"));
    assert!(!canonical_str.contains("\t"));
    assert_eq!(canonical_str, r#"{"key1":[1,2,3],"key2":"value"}"#);
}

#[test]
fn test_in_toto_statement_schema_compliance() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let builder = ActionReceiptBuilder::new(&action, &decision);

    let domain = builder.build_domain().unwrap();
    let statement = domain.to_in_toto_statement().unwrap();

    // 1. _type MUST be https://in-toto.io/Statement/v1
    assert_eq!(statement.statement_type, InTotoStatement::STATEMENT_TYPE);
    assert_eq!(statement.statement_type, "https://in-toto.io/Statement/v1");

    // 2. subject MUST contain action hash and resource
    assert!(!statement.subject.is_empty());
    assert_eq!(statement.subject[0].name, action.resource.as_str());
    assert_eq!(
        statement.subject[0].digest.get("sha256").unwrap(),
        &action_hash.to_hex()
    );

    // 3. predicateType MUST be https://relay.dev/ActionReceipt/v1
    assert_eq!(statement.predicate_type, InTotoStatement::PREDICATE_TYPE);
    assert_eq!(
        statement.predicate_type,
        "https://relay.dev/ActionReceipt/v1"
    );

    // 4. predicate MUST have required evidence sections
    assert_eq!(statement.predicate.receipt_id, domain.receipt_id);
    assert_eq!(statement.predicate.action_id, domain.action_id);
    assert_eq!(statement.predicate.session_id, domain.session_id);
    assert_eq!(statement.predicate.action_hash, action_hash);
    assert!(statement
        .predicate
        .epistemology
        .get("asserted_by_relay")
        .is_some());
}

#[test]
fn test_dsse_envelope_schema_compliance() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = create_test_signer();
    let builder = ActionReceiptBuilder::new(&action, &decision);

    let receipt = builder.build_and_sign(&signer).unwrap();
    let envelope = &receipt.dsse_envelope;

    // 1. payloadType
    assert_eq!(envelope.payload_type, DsseEnvelope::PAYLOAD_TYPE);
    assert_eq!(envelope.payload_type, "application/vnd.in-toto+json");

    // 2. payload is valid base64
    let payload_bytes = base64_decode(&envelope.payload).expect("Payload must be valid base64");
    assert!(!payload_bytes.is_empty());

    // 3. Payload decodes to valid in-toto Statement
    let parsed: InTotoStatement =
        serde_json::from_slice(&payload_bytes).expect("Decoded payload must be InTotoStatement");
    assert_eq!(parsed.statement_type, "https://in-toto.io/Statement/v1");

    // 4. signatures non-empty
    assert_eq!(envelope.signatures.len(), 1);
    assert!(!envelope.signatures[0].sig.is_empty());
    assert_eq!(envelope.signatures[0].keyid, "test-ed25519-signer-v1");
}

#[test]
fn test_malformed_json_graceful_handling() {
    let invalid_json = b"{\"invalid\": json, without quotes}";
    let parse_res: Result<InTotoStatement, _> = serde_json::from_slice(invalid_json);
    assert!(
        parse_res.is_err(),
        "Malformed JSON must be rejected gracefully without panic"
    );

    let invalid_base64 = "!!!not base64!!!";
    let decode_res = base64_decode(invalid_base64);
    assert!(
        decode_res.is_err(),
        "Malformed base64 must be rejected gracefully"
    );
}
