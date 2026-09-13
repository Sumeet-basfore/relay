mod common;

use common::*;
use relay_domain::{Ledger, SequenceNumber};
use relay_ledger::SqliteLedger;
use std::time::Instant;

#[tokio::test]
async fn test_ledger_performance_targets() {
    let ledger = SqliteLedger::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    let num_entries = 100;
    let mut prev_hash = genesis.entry_hash;
    let mut append_durations = Vec::with_capacity(num_entries);

    // 1. Measure Append Latency
    for i in 1..=num_entries {
        let receipt = build_signed_test_receipt(&signer, &format!("perf_tool_{i}"), prev_hash);
        let start = Instant::now();
        let entry = ledger.append(&receipt).await.unwrap();
        append_durations.push(start.elapsed());
        prev_hash = entry.entry_hash;
    }

    append_durations.sort();
    let p50 = append_durations[num_entries / 2];
    let p95 = append_durations[(num_entries as f64 * 0.95) as usize];
    let p99 = append_durations[(num_entries as f64 * 0.99) as usize];

    println!(
        "Ledger Append Latency ({} entries): p50={:?}, p95={:?}, p99={:?}",
        num_entries, p50, p95, p99
    );

    // In-memory/WAL append latency should be well under 10ms
    assert!(
        p95.as_millis() < 15,
        "p95 append latency should be under 15ms, was {:?}",
        p95
    );

    // 2. Measure Verification Throughput
    let verify_start = Instant::now();
    let report = ledger.verify(None).await.unwrap();
    let verify_elapsed = verify_start.elapsed();

    assert!(report.status.is_valid());
    let rate = (report.total_verified_entries as f64) / verify_elapsed.as_secs_f64();
    println!(
        "Ledger Verification: {} entries in {:?} ({:.0} entries/sec)",
        report.total_verified_entries, verify_elapsed, rate
    );

    // 3. Measure Point Query Latency
    let query_start = Instant::now();
    for i in 1..=50 {
        let _ = ledger.get_by_sequence(SequenceNumber(i)).await.unwrap();
    }
    let query_elapsed = query_start.elapsed();
    let avg_query = query_elapsed / 50;
    println!("Point Query Latency (avg over 50 queries): {:?}", avg_query);
    assert!(
        avg_query.as_millis() < 2,
        "Average query latency should be under 2ms, was {:?}",
        avg_query
    );
}
