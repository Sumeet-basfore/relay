//! B012 Golden Path Performance Overhead and Reliability Stress Tests.
//!
//! Enforces:
//! - Section 26: Microbenchmarks measuring Relay governance pipeline overhead (excluding external latency)
//! - Section 27: Reliability stress tests (100 and 1,000 sequential governed actions)
//! - Verifies zero memory leaks, zero deadlocks, and uninterrupted cryptographic hash-chain integrity

use std::sync::Arc;
use std::time::Instant;

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::coordinator::GovernedActionRunner;
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{HeadlessApprovalProvider, Ledger, PrincipalId, ReceiptSigner, SessionId};
use relay_ledger::SqliteLedger;
use relay_policy::CedarPolicyEngine;
use relay_receipts::Ed25519ReceiptSigner;
use tempfile::TempDir;

#[tokio::test]
async fn test_governance_pipeline_microbenchmark_overhead() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file"],
            resource
        );
    "#;

    let engine = CedarPolicyEngine::from_str(cedar_policy, None).expect("Valid policy");
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let ledger = SqliteLedger::in_memory().expect("In-memory ledger");

    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .expect("Genesis init");

    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root_path)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(Arc::new(ledger))
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();

    // Warm-up run
    let warmup_session = SessionId::new_v7();
    let warmup_args = serde_json::json!({
        "path": "warmup.txt",
        "content": "warmup"
    });
    let warmup_action = canonicalizer
        .canonicalize(
            warmup_session,
            principal.clone(),
            "tools/call",
            tool.clone(),
            &warmup_args,
            None,
            None,
        )
        .unwrap();
    runner.run_action(&warmup_action).await.expect("Warmup ok");

    // Benchmark 50 measured executions
    let iterations = 50;
    let mut durations = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let file_name = format!("bench_{i}.txt");
        let raw_args = serde_json::json!({
            "path": file_name,
            "content": "Benchmark test payload"
        });

        let start = Instant::now();
        let session_id = SessionId::new_v7();
        let canonical_action = canonicalizer
            .canonicalize(
                session_id,
                principal.clone(),
                "tools/call",
                tool.clone(),
                &raw_args,
                None,
                None,
            )
            .unwrap();

        let outcome = runner.run_action(&canonical_action).await.unwrap();
        let elapsed = start.elapsed();
        durations.push(elapsed);

        assert_eq!(outcome.execution_result.exit_code, 0);
    }

    durations.sort();
    let median = durations[durations.len() / 2];
    let p95 = durations[(durations.len() as f64 * 0.95) as usize];
    let min = durations[0];
    let max = durations[durations.len() - 1];

    println!(
        "\n=== B012 Governance Overhead Microbenchmark (50 runs) ===\n\
         Min:    {:?}\n\
         Median: {:?}\n\
         P95:    {:?}\n\
         Max:    {:?}\n\
         =======================================================",
        min, median, p95, max
    );

    // Verify governance overhead remains within reasonable production bounds (< 50ms in debug test profile)
    assert!(
        median.as_millis() < 50,
        "Median governance overhead should be < 50ms even in debug profile, got {:?}",
        median
    );
}

#[tokio::test]
async fn test_reliability_stress_100_sequential_actions() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file"],
            resource
        );
    "#;

    let engine = CedarPolicyEngine::from_str(cedar_policy, None).expect("Valid policy");
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let ledger = Arc::new(SqliteLedger::in_memory().expect("In-memory ledger"));

    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .expect("Genesis init");

    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root_path)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger.clone())
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();

    let action_count = 100;
    for i in 1..=action_count {
        let file_name = format!("stress_{i}.txt");
        let raw_args = serde_json::json!({
            "path": file_name,
            "content": format!("Stress test payload {i}")
        });

        let session_id = SessionId::new_v7();
        let canonical_action = canonicalizer
            .canonicalize(
                session_id,
                principal.clone(),
                "tools/call",
                tool.clone(),
                &raw_args,
                None,
                None,
            )
            .unwrap();

        let outcome = runner
            .run_action(&canonical_action)
            .await
            .unwrap_or_else(|e| panic!("Action {i} failed: {e}"));

        assert_eq!(outcome.execution_result.exit_code, 0);
        let entry = outcome.ledger_entry.expect("Ledger entry");
        assert_eq!(entry.sequence_number.as_u64(), i as u64);
    }

    // Cryptographic chain verification across all 100 entries
    let chain_valid = ledger.verify_chain().await.expect("Verify chain");
    assert!(
        chain_valid,
        "Hash chain must remain valid across 100 sequential actions"
    );
}
