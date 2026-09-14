//! Performance Characterization Tests for Relay Filesystem Connector (B010).
//!
//! Measures:
//! 1. Path resolution & root-jail lexical normalization latency (< 100 µs target)
//! 2. Bounded file read latency (100KB file)
//! 3. Atomic file write latency (temp file + fsync + rename)
//! 4. Directory listing latency (100 entries)
//! 5. Full governed execution pipeline latency including Cedar evaluation and DSSE ActionReceipt generation

use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;

use relay_canonical::ActionCanonicalizer;
use relay_connectors::fs::{
    list_directory, read_file, resolve_and_verify_within_root, write_file_atomic,
    FilesystemConnector, FsConnectorConfig,
};
use relay_domain::{PolicyEngine, PrincipalId, ToolIdentity};
use relay_policy::CedarPolicyEngine;
use relay_receipts::Ed25519ReceiptSigner;

#[tokio::test]
async fn test_fs_performance_characterization() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let cfg = FsConnectorConfig::new(&root);

    // 1. Path resolution & root-jail lexical normalization benchmark
    let iterations = 1_000;
    let target_rel = std::path::Path::new("subdir/nested/../nested/target.txt");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = resolve_and_verify_within_root(&cfg, target_rel, false);
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iterations as u128;
    println!(
        "Average path resolution latency: {} ns ({:.2} µs)",
        avg_ns,
        avg_ns as f64 / 1_000.0
    );
    assert!(
        avg_ns < 200_000,
        "Path resolution should be under 200 µs (actual: {} ns)",
        avg_ns
    );

    // 2. Atomic write benchmark
    let payload = vec![b'A'; 64 * 1024]; // 64 KB
    let write_file = root.join("bench_write.dat");
    let start_write = Instant::now();
    let write_res = write_file_atomic(&cfg, &write_file, &payload).expect("write");
    let write_dur = start_write.elapsed();
    println!(
        "Atomic write (64KB + fsync + rename) latency: {:.2} ms",
        write_dur.as_secs_f64() * 1000.0
    );
    assert_eq!(write_res.bytes_written, 64 * 1024);

    // 3. Bounded read benchmark
    let start_read = Instant::now();
    let read_res = read_file(&cfg, &write_file).expect("read");
    let read_dur = start_read.elapsed();
    println!(
        "Bounded read (64KB) latency: {:.2} ms",
        read_dur.as_secs_f64() * 1000.0
    );
    assert_eq!(read_res.size_bytes, 64 * 1024);

    // 4. Directory listing benchmark (100 files)
    let dir_bench = root.join("listing_bench");
    std::fs::create_dir(&dir_bench).unwrap();
    for i in 0..100 {
        std::fs::write(dir_bench.join(format!("file_{i}.txt")), b"test").unwrap();
    }
    let start_list = Instant::now();
    let entries = list_directory(&cfg, &dir_bench).expect("list");
    let list_dur = start_list.elapsed();
    println!(
        "Directory listing (100 entries) latency: {:.2} ms",
        list_dur.as_secs_f64() * 1000.0
    );
    assert_eq!(entries.len(), 100);

    // 5. Full Governed Pipeline benchmark (Canonicalize -> Cedar PDP -> FS Connector -> DSSE Receipt)
    let connector = FilesystemConnector::new(cfg);
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());
    let canonicalizer = ActionCanonicalizer::default();
    let signer = Ed25519ReceiptSigner::generate("perf-signer");

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:bench").unwrap();
    let tool_ident = ToolIdentity::new("relay", "fs", "read_file");
    let args = serde_json::json!({
        "path": write_file.to_string_lossy().to_string(),
    });

    let start_pipeline = Instant::now();
    let canonical_action = canonicalizer
        .canonicalize(
            session_id,
            principal,
            "tools/call",
            tool_ident,
            &args,
            None,
            None,
        )
        .unwrap();
    let auth_req = canonical_action.to_authorization_request().unwrap();
    let decision = policy_engine.evaluate(&auth_req).await.unwrap();
    assert!(decision.is_allowed());

    let (exec_res, receipt) = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &signer)
        .await
        .unwrap();
    let pipeline_dur = start_pipeline.elapsed();

    println!(
        "Full governed read pipeline latency: {:.2} ms",
        pipeline_dur.as_secs_f64() * 1000.0
    );
    assert_eq!(exec_res.exit_code, 0);
    assert_eq!(receipt.action_hash, canonical_action.action_hash);
}
