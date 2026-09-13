mod common;

use common::*;
use relay_receipts::{
    base64_decode, base64_encode, ActionReceiptBuilder, Ed25519ReceiptSigner, ReceiptVerifier,
    VerificationResult,
};

#[test]
fn test_ed25519_sign_and_verify_success() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = Ed25519ReceiptSigner::generate("signer-01");
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let receipt = builder
        .build_and_sign(&signer)
        .expect("Should build and sign");

    let result = verifier.verify_receipt(&receipt, Some(&action_hash), None);
    assert!(
        result.is_valid(),
        "Verification with matching key must succeed: {:?}",
        result
    );
}

#[test]
fn test_verification_with_wrong_public_key_fails() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = Ed25519ReceiptSigner::generate("signer-01");
    let wrong_signer = Ed25519ReceiptSigner::generate("signer-02");
    let verifier = ReceiptVerifier::new(wrong_signer.verifying_key());

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let receipt = builder
        .build_and_sign(&signer)
        .expect("Should build and sign");

    let result = verifier.verify_receipt(&receipt, None, None);
    match result {
        VerificationResult::InvalidSignature { .. } => {}
        other => panic!("Expected InvalidSignature, got: {:?}", other),
    }
}

#[test]
fn test_verification_with_corrupted_payload_fails() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = Ed25519ReceiptSigner::generate("signer-01");
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let mut receipt = builder
        .build_and_sign(&signer)
        .expect("Should build and sign");

    // Tamper with payload by corrupting base64 payload bytes
    let payload_bytes = base64_decode(&receipt.dsse_envelope.payload).unwrap();
    let mut tampered_bytes = payload_bytes;
    tampered_bytes[10] ^= 0xFF; // Flip bits
    receipt.dsse_envelope.payload = base64_encode(&tampered_bytes);

    let result = verifier.verify_receipt(&receipt, None, None);
    assert!(
        !result.is_valid(),
        "Tampered payload must fail verification"
    );
}

#[test]
fn test_verification_with_corrupted_signature_fails() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = Ed25519ReceiptSigner::generate("signer-01");
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let mut receipt = builder
        .build_and_sign(&signer)
        .expect("Should build and sign");

    // Tamper with signature
    let sig_bytes = base64_decode(&receipt.dsse_envelope.signatures[0].sig).unwrap();
    let mut tampered_sig = sig_bytes;
    tampered_sig[5] ^= 0xAA;
    receipt.dsse_envelope.signatures[0].sig = base64_encode(&tampered_sig);

    let result = verifier.verify_receipt(&receipt, None, None);
    match result {
        VerificationResult::InvalidSignature { .. } => {}
        other => panic!("Expected InvalidSignature, got: {:?}", other),
    }
}

#[test]
fn test_verification_with_wrong_payload_type_fails() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = Ed25519ReceiptSigner::generate("signer-01");
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let mut receipt = builder
        .build_and_sign(&signer)
        .expect("Should build and sign");

    // Tamper with payload_type
    receipt.dsse_envelope.payload_type = "application/json".to_string();

    let result = verifier.verify_receipt(&receipt, None, None);
    match result {
        VerificationResult::UnsupportedSchema(reason) => {
            assert!(reason.contains("Unsupported DSSE payloadType"));
        }
        other => panic!("Expected UnsupportedSchema, got: {:?}", other),
    }
}

#[test]
fn test_public_key_export_and_import() {
    let signer = Ed25519ReceiptSigner::generate("signer-export");
    let exported_bytes = signer.verifying_key().to_bytes();

    let imported_key = ed25519_dalek::VerifyingKey::from_bytes(&exported_bytes)
        .expect("Should deserialize verifying key");

    assert_eq!(signer.verifying_key(), imported_key);

    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let builder = ActionReceiptBuilder::new(&action, &decision);
    let receipt = builder.build_and_sign(&signer).unwrap();

    let verifier = ReceiptVerifier::new(imported_key);
    let result = verifier.verify_receipt(&receipt, Some(&action_hash), None);
    assert!(result.is_valid());
}

#[test]
fn test_multiple_signers_produce_distinct_signatures() {
    let signer_a = Ed25519ReceiptSigner::generate("signer-A");
    let signer_b = Ed25519ReceiptSigner::generate("signer-B");

    assert_ne!(
        signer_a.verifying_key().to_bytes(),
        signer_b.verifying_key().to_bytes()
    );

    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);

    let receipt_a = ActionReceiptBuilder::new(&action, &decision)
        .build_and_sign(&signer_a)
        .unwrap();
    let receipt_b = ActionReceiptBuilder::new(&action, &decision)
        .build_and_sign(&signer_b)
        .unwrap();

    assert_ne!(
        receipt_a.dsse_envelope.signatures[0].sig,
        receipt_b.dsse_envelope.signatures[0].sig
    );
}

#[test]
fn test_envelope_direct_verification() {
    let signer = Ed25519ReceiptSigner::generate("envelope-signer");
    let payload = b"{\"hello\": \"world\"}";
    let envelope = signer
        .sign_payload_bytes_sync(relay_domain::DsseEnvelope::PAYLOAD_TYPE, payload)
        .unwrap();

    let verifier = ReceiptVerifier::new(signer.verifying_key());
    let res = verifier.verify_envelope(&envelope);
    assert!(res.is_ok());

    let other_signer = Ed25519ReceiptSigner::generate("other");
    let other_verifier = ReceiptVerifier::new(other_signer.verifying_key());
    let other_res = other_verifier.verify_envelope(&envelope);
    assert!(other_res.is_err());
}
