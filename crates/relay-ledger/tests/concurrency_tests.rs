mod common;

use common::*;
use relay_domain::Ledger;
use relay_ledger::SqliteLedger;
use std::collections::HashSet;
use std::sync::Arc;

#[tokio::test]
async fn test_concurrent_appends_single_writer_actor() {
    let ledger = SqliteLedger::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    let ledger_arc = Arc::new(ledger);
    let signer_arc = Arc::new(signer);
    let mut handles = Vec::new();

    // Spawn 20 concurrent tasks attempting simultaneous appends
    for i in 0..20 {
        let l = Arc::clone(&ledger_arc);
        let s = Arc::clone(&signer_arc);
        let dummy_parent = genesis.entry_hash;

        let handle = tokio::spawn(async move {
            let receipt =
                build_signed_test_receipt(&s, &format!("concurrent_tool_{i}"), dummy_parent);
            l.append(&receipt).await
        });
        handles.push(handle);
    }

    let mut sequence_numbers = Vec::new();
    for handle in handles {
        let res = handle.await.expect("Tokio task panicked");
        let entry = res.expect("Append failed during concurrent write");
        sequence_numbers.push(entry.sequence_number.as_u64());
    }

    assert_eq!(sequence_numbers.len(), 20);

    // Ensure all sequence numbers from 1 to 20 were assigned with zero gaps or collisions
    sequence_numbers.sort();
    let expected: Vec<u64> = (1..=20).collect();
    assert_eq!(
        sequence_numbers, expected,
        "Sequences must be contiguous without duplicates"
    );

    let set: HashSet<u64> = sequence_numbers.into_iter().collect();
    assert_eq!(set.len(), 20, "Every sequence number must be unique");

    // Total count in database must be 21 (1 genesis + 20 appends)
    let total_count = ledger_arc.count().await.unwrap();
    assert_eq!(total_count, 21);

    // Hash chain verification across all 21 entries must be 100% valid
    let report = ledger_arc.verify(None).await.unwrap();
    assert!(
        report.status.is_valid(),
        "Concurrent chain must remain valid"
    );
    assert_eq!(report.total_verified_entries, 21);
    assert_eq!(report.head_sequence, 20);
}
