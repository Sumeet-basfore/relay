mod common;

use common::*;
use relay_ledger::{LedgerVerificationStatus, LedgerVerifier, SqliteStorageEngine};

#[test]
fn test_tamper_envelope_bytes_detected_as_payload_mismatch() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let receipt = build_signed_test_receipt(&signer, "action_1", genesis.entry_hash);
    let _entry = engine.append(&receipt).unwrap();

    // Verify initially valid
    let rep = LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    assert!(rep.status.is_valid());

    // Simulate disk/database tampering by dropping trigger and mutating envelope byte
    let conn = engine.raw_connection_mut();
    conn.execute_batch("DROP TRIGGER prevent_receipts_update;")
        .unwrap();
    conn.execute(
        "UPDATE receipts SET dsse_envelope = X'000102030405' WHERE sequence_number = 1",
        [],
    )
    .unwrap();

    // Verification must detect tampering
    let rep_tampered =
        LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    match rep_tampered.status {
        LedgerVerificationStatus::PayloadHashMismatch {
            sequence_number, ..
        } => {
            assert_eq!(sequence_number, 1);
        }
        other => panic!("Expected PayloadHashMismatch, got {other:?}"),
    }
}

#[test]
fn test_tamper_entry_hash_detected_as_entry_hash_mismatch() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let receipt = build_signed_test_receipt(&signer, "action_1", genesis.entry_hash);
    let _entry = engine.append(&receipt).unwrap();

    // Tamper with entry_hash directly
    let conn = engine.raw_connection_mut();
    conn.execute_batch("DROP TRIGGER prevent_ledger_update;")
        .unwrap();
    conn.execute(
        "UPDATE ledger_entries SET entry_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE sequence_number = 1",
        [],
    )
    .unwrap();

    let rep = LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    match rep.status {
        LedgerVerificationStatus::EntryHashMismatch {
            sequence_number, ..
        } => {
            assert_eq!(sequence_number, 1);
        }
        other => panic!("Expected EntryHashMismatch, got {other:?}"),
    }
}

#[test]
fn test_tamper_parent_linkage_detected_as_broken_chain() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let receipt1 = build_signed_test_receipt(&signer, "action_1", genesis.entry_hash);
    let entry1 = engine.append(&receipt1).unwrap();

    let receipt2 = build_signed_test_receipt(&signer, "action_2", entry1.entry_hash);
    let _entry2 = engine.append(&receipt2).unwrap();

    // Tamper with parent_hash of sequence 2
    let conn = engine.raw_connection_mut();
    conn.execute_batch("DROP TRIGGER prevent_ledger_update;")
        .unwrap();
    conn.execute(
        "UPDATE ledger_entries SET parent_hash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE sequence_number = 2",
        [],
    )
    .unwrap();

    let rep = LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    match rep.status {
        LedgerVerificationStatus::BrokenChain {
            sequence_number, ..
        } => {
            assert_eq!(sequence_number, 2);
        }
        other => panic!("Expected BrokenChain, got {other:?}"),
    }
}

#[test]
fn test_deleted_row_detected_as_sequence_gap() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let receipt1 = build_signed_test_receipt(&signer, "action_1", genesis.entry_hash);
    let entry1 = engine.append(&receipt1).unwrap();

    let receipt2 = build_signed_test_receipt(&signer, "action_2", entry1.entry_hash);
    let _entry2 = engine.append(&receipt2).unwrap();

    // Drop triggers and foreign keys to delete row 1
    let conn = engine.raw_connection_mut();
    conn.execute_batch(
        "PRAGMA foreign_keys = OFF;
         DROP TRIGGER prevent_ledger_delete;
         DROP TRIGGER prevent_receipts_delete;
         DELETE FROM receipts WHERE sequence_number = 1;
         DELETE FROM ledger_entries WHERE sequence_number = 1;",
    )
    .unwrap();

    let rep = LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    match rep.status {
        LedgerVerificationStatus::SequenceGap { expected, actual } => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        other => panic!("Expected SequenceGap, got {other:?}"),
    }
}

#[test]
fn test_corrupted_signature_detected_as_invalid_signature() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());
    let pubkey_bytes: [u8; 32] = signer.export_public_key().try_into().unwrap();

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let mut receipt = build_signed_test_receipt(&signer, "action_1", genesis.entry_hash);

    // Corrupt signature in envelope
    let mut bad_sig = receipt.dsse_envelope.signatures[0].sig.clone();
    bad_sig.replace_range(0..4, "AAAA");
    receipt.dsse_envelope.signatures[0].sig = bad_sig;

    // Append to engine
    let _entry = engine.append(&receipt).unwrap();

    let rep = LedgerVerifier::verify_connection(engine.raw_connection(), Some(&pubkey_bytes), None)
        .unwrap();
    match rep.status {
        LedgerVerificationStatus::InvalidSignature {
            sequence_number, ..
        } => {
            assert_eq!(sequence_number, 1);
        }
        other => panic!("Expected InvalidSignature, got {other:?}"),
    }
}
