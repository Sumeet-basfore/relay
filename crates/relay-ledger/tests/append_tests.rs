mod common;

use common::*;
use relay_domain::{Ledger, SequenceNumber};
use relay_ledger::{SqliteLedger, SqliteStorageEngine};

#[tokio::test]
async fn test_genesis_initialization() {
    let ledger = SqliteLedger::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    // Initialize genesis
    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    assert_eq!(genesis.sequence_number.as_u64(), 0);
    assert_eq!(
        genesis.previous_receipt_hash,
        relay_ledger::genesis_parent_hash()
    );

    // Second initialization must be idempotent
    let genesis2 = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();
    assert_eq!(genesis.entry_hash, genesis2.entry_hash);

    let count = ledger.count().await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_append_receipts_sequential() {
    let ledger = SqliteLedger::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    // Append first receipt
    let receipt1 = build_signed_test_receipt(&signer, "get_repo", genesis.entry_hash);
    let entry1 = ledger.append(&receipt1).await.unwrap();

    assert_eq!(entry1.sequence_number.as_u64(), 1);
    assert_eq!(entry1.previous_receipt_hash, genesis.entry_hash);
    assert_eq!(entry1.receipt_id, receipt1.receipt_id);

    // Append second receipt
    let receipt2 = build_signed_test_receipt(&signer, "create_issue", entry1.entry_hash);
    let entry2 = ledger.append(&receipt2).await.unwrap();

    assert_eq!(entry2.sequence_number.as_u64(), 2);
    assert_eq!(entry2.previous_receipt_hash, entry1.entry_hash);
    assert_eq!(entry2.receipt_id, receipt2.receipt_id);

    // Verify counts and reads
    assert_eq!(ledger.count().await.unwrap(), 3);

    let fetched1 = ledger.get_by_sequence(SequenceNumber(1)).await.unwrap();
    assert!(fetched1.is_some());
    assert_eq!(fetched1.unwrap().entry_hash, entry1.entry_hash);

    let fetched_r2 = ledger
        .get_receipt_by_id(&receipt2.receipt_id)
        .await
        .unwrap();
    assert!(fetched_r2.is_some());
    assert_eq!(fetched_r2.unwrap().receipt_id, receipt2.receipt_id);

    // Verify recent list
    let recent = ledger.list_recent(10).await.unwrap();
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].sequence_number.as_u64(), 2); // Descending order
}

#[test]
fn test_immutability_triggers_prevent_update_and_delete() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let receipt = build_signed_test_receipt(&signer, "list_issues", genesis.entry_hash);
    let _entry = engine.append(&receipt).unwrap();

    let conn = engine.raw_connection_mut();

    // 1. Attempt UPDATE on ledger_entries - must fail by trigger
    let update_res = conn.execute(
        "UPDATE ledger_entries SET entry_hash = '1111111111111111111111111111111111111111111111111111111111111111' WHERE sequence_number = 1",
        [],
    );
    assert!(update_res.is_err());
    let err_msg = update_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("RELAY_STORAGE_INVARIANT_VIOLATION")
            && err_msg.contains("strictly append-only"),
        "Expected append-only trigger violation, got: {err_msg}"
    );

    // 2. Attempt DELETE from ledger_entries - must fail by trigger
    let delete_res = conn.execute("DELETE FROM ledger_entries WHERE sequence_number = 1", []);
    assert!(delete_res.is_err());
    let err_msg = delete_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("RELAY_STORAGE_INVARIANT_VIOLATION")
            && err_msg.contains("cannot be deleted"),
        "Expected delete trigger violation, got: {err_msg}"
    );

    // 3. Attempt UPDATE on receipts - must fail by trigger
    let update_rcpt = conn.execute(
        "UPDATE receipts SET tool_name = 'hacked' WHERE sequence_number = 1",
        [],
    );
    assert!(update_rcpt.is_err());
    let err_msg = update_rcpt.unwrap_err().to_string();
    assert!(
        err_msg.contains("RELAY_STORAGE_INVARIANT_VIOLATION")
            && err_msg.contains("cryptographically immutable"),
        "Expected immutable receipts trigger violation, got: {err_msg}"
    );

    // 4. Attempt DELETE from receipts - must fail by trigger
    let delete_rcpt = conn.execute("DELETE FROM receipts WHERE sequence_number = 1", []);
    assert!(delete_rcpt.is_err());
    let err_msg = delete_rcpt.unwrap_err().to_string();
    assert!(
        err_msg.contains("RELAY_STORAGE_INVARIANT_VIOLATION")
            && err_msg.contains("cannot be deleted"),
        "Expected delete receipts trigger violation, got: {err_msg}"
    );
}
