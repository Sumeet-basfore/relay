mod common;

use common::*;
use relay_ledger::{LedgerVerificationStatus, LedgerVerifier, SqliteStorageEngine};
use relay_receipts::Ed25519ReceiptSigner;

#[test]
fn test_signature_verification_with_correct_and_wrong_keys() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_bytes: [u8; 32] = signer.export_public_key().try_into().unwrap();
    let pubkey_hex = hex::encode(pubkey_bytes);

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let receipt = build_signed_test_receipt(&signer, "action_1", genesis.entry_hash);
    let _entry = engine.append(&receipt).unwrap();

    // 1. Verify with matching public key -> must be Valid
    let report_valid =
        LedgerVerifier::verify_connection(engine.raw_connection(), Some(&pubkey_bytes), None)
            .unwrap();
    assert!(report_valid.status.is_valid());

    // 2. Verify with auto-detected key from node_identity table -> must be Valid
    let report_auto =
        LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    assert!(report_auto.status.is_valid());

    // 3. Verify with a different, wrong public key -> must fail with InvalidSignature
    let wrong_signer = Ed25519ReceiptSigner::generate("wrong-signer");
    let wrong_pubkey: [u8; 32] = wrong_signer.export_public_key().try_into().unwrap();

    let report_wrong =
        LedgerVerifier::verify_connection(engine.raw_connection(), Some(&wrong_pubkey), None)
            .unwrap();
    match report_wrong.status {
        LedgerVerificationStatus::InvalidSignature {
            sequence_number, ..
        } => {
            assert_eq!(sequence_number, 1);
        }
        other => panic!("Expected InvalidSignature, got {other:?}"),
    }
}
