mod common;

use common::*;
use relay_domain::Ledger;
use relay_ledger::{compute_entry_hash, compute_payload_hash, SqliteLedger};

#[tokio::test]
async fn test_hash_chain_continuity_over_many_entries() {
    let ledger = SqliteLedger::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    let mut prev_hash = genesis.entry_hash;
    let mut entries = vec![genesis];

    for i in 1..=15 {
        let receipt = build_signed_test_receipt(&signer, &format!("action_{i}"), prev_hash);
        let entry = ledger.append(&receipt).await.unwrap();

        assert_eq!(entry.sequence_number.as_u64(), i as u64);
        assert_eq!(entry.previous_receipt_hash, prev_hash);

        // Manually compute expected entry hash matching A006 §5.1
        let canonical_dsse = serde_jcs::to_vec(&receipt.dsse_envelope).unwrap();
        let payload_hash = compute_payload_hash(&canonical_dsse);
        let expected_entry_hash = compute_entry_hash(i as u64, &prev_hash, &payload_hash);

        assert_eq!(entry.entry_hash, expected_entry_hash);

        prev_hash = entry.entry_hash;
        entries.push(entry);
    }

    // Verify whole chain via trait
    let verified = ledger.verify_chain().await.unwrap();
    assert!(verified);

    // Verify via detailed report
    let pubkey_bytes = signer.export_public_key();
    let arr: [u8; 32] = pubkey_bytes.try_into().unwrap();
    let report = ledger.verify(Some(&arr)).await.unwrap();

    assert!(report.status.is_valid());
    assert_eq!(report.total_verified_entries, 16); // 1 genesis + 15 receipts
    assert_eq!(report.head_sequence, 15);
    assert_eq!(report.head_hash, prev_hash.to_hex());

    // Verify starting from sequence 5
    let report_partial = ledger.verify_from_seq(5, Some(&arr)).await.unwrap();
    assert!(report_partial.status.is_valid());
    assert_eq!(report_partial.total_verified_entries, 11); // seq 5 to 15
    assert_eq!(report_partial.head_sequence, 15);
}
