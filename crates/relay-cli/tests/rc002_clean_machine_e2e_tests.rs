//! RC002 Clean-Machine & Production Distribution End-to-End Test Suite.
//!
//! Validates:
//! - Cold-start execution in clean environments (isolated HOME, empty cache/config)
//! - `relay doctor` diagnostics on fresh machines
//! - Deterministic configuration loading and fail-closed behavior on missing explicit configs
//! - Full lifecycle of governed operations (FS write/read) -> DSSE receipt -> SQLite ledger append
//! - Ledger verification (`relay verify`) and receipt query (`relay receipt list`)
//! - Upgrade simulation: reopening existing ledger, appending new records, verifying complete hash chain
//! - Fail-closed security detection on ledger corruption / tampering

use assert_cmd::Command;
use chrono::Utc;
use predicates::prelude::*;
use relay_canonical::{ActionCanonicalizer, CanonicalAction, ToolIdentity};
use relay_connectors::coordinator::GovernedActionRunner;
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, ActionId, ApprovalProvider, Digest, ExecutionEnvironment, ExecutionId,
    ExecutionObservationStatus, ExecutionRoute, ExitCode, OutputHash, PolicyDecision, PrincipalId,
    ReceiptSigner, ResourceUri, SchemaDigest, SequenceNumber, SessionId,
};
use relay_ledger::{LedgerVerifier, SqliteLedger, SqliteStorageEngine};
use relay_policy::CedarPolicyEngine;
use relay_receipts::{ActionReceiptBuilder, Ed25519ReceiptSigner};
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

struct NeverApprovalProvider;

#[async_trait::async_trait]
impl ApprovalProvider for NeverApprovalProvider {
    async fn request_approval(
        &self,
        _approval: &mut relay_domain::Approval,
    ) -> Result<(), relay_domain::ApprovalError> {
        Err(relay_domain::ApprovalError::NonInteractiveMode)
    }
}

fn create_test_action(tool_name: &str) -> (CanonicalAction, ActionHash) {
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse(&format!("relay.fs.{tool_name}")).unwrap();
    let resource = ResourceUri::parse("file:///tmp/test.txt").unwrap();
    let args = serde_json::json!({ "path": "/tmp/test.txt" });
    let schema_digest = SchemaDigest::compute(b"{}");
    let env = ExecutionEnvironment::current();

    let mut action = CanonicalAction {
        action_id: ActionId::new_v7(),
        session_id,
        principal,
        mcp_method: "tools/call".to_string(),
        tool,
        resource,
        canonical_arguments: args,
        schema_digest,
        environment: env,
        action_hash: ActionHash::compute(b"dummy"),
        canonical_bytes: Vec::new(),
        created_at: Utc::now(),
    };

    let hash = ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
    action.action_hash = hash;
    (action, hash)
}

#[test]
fn test_rc002_clean_machine_doctor() {
    let clean_home = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.env_clear()
        .env("HOME", clean_home.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("=== Relay System Health"))
        .stdout(predicate::str::contains("NOT CREATED"))
        .stdout(predicate::str::contains("DEFAULT (in-binary bundled)"));
}

#[test]
fn test_rc002_missing_explicit_config_fails_closed() {
    let clean_home = tempdir().unwrap();
    let non_existent_config = clean_home.path().join("missing_relay.toml");

    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.env_clear()
        .env("HOME", clean_home.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("--config")
        .arg(&non_existent_config)
        .arg("doctor")
        .assert()
        .failure()
        .code(ExitCode::ConfigError.as_i32())
        .stderr(predicate::str::contains("Configuration file not found"));
}

#[tokio::test]
async fn test_rc002_clean_machine_full_governed_lifecycle() {
    let env_dir = tempdir().unwrap();
    let workspace_dir = env_dir.path().join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();

    let db_path = env_dir.path().join("storage").join("ledger.db");
    let key_path = env_dir.path().join("keys").join("signing_key.seed");

    // 1. Generate and save key
    let signer = Arc::new(Ed25519ReceiptSigner::generate("rc002-production-key-01"));
    signer.save_to_file(&key_path).unwrap();

    // 2. Initialize Ledger with genesis
    let ledger = Arc::new(SqliteLedger::open(&db_path).unwrap());
    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    // 3. Set up Policy Engine & Connectors
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file", Relay::Action::"fs.read_file"],
            resource
        );
    "#;
    let engine = Arc::new(CedarPolicyEngine::from_str(cedar_policy, None).unwrap());
    let cred_provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(cred_provider).await;

    let fs_config = FsConnectorConfig::new(workspace_dir.clone());
    let fs_connector = Arc::new(FilesystemConnector::new(fs_config));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(NeverApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    // 4. Execute governed action: fs.write_file
    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();

    let test_file = workspace_dir.join("clean_machine_artifact.txt");
    let raw_args = serde_json::json!({
        "path": test_file.to_str().unwrap(),
        "content": "RC002 clean machine governed execution validated successfully\n"
    });

    let canonical_action = canonicalizer
        .canonicalize(
            session_id,
            principal,
            "tools/call",
            tool,
            &raw_args,
            None,
            None,
        )
        .unwrap();

    let outcome = runner.run_action(&canonical_action).await.unwrap();
    assert!(outcome.ledger_entry.is_some());
    assert!(test_file.exists());
    let content = fs::read_to_string(&test_file).unwrap();
    assert_eq!(
        content,
        "RC002 clean machine governed execution validated successfully\n"
    );

    // 5. Verify ledger via CLI
    let mut verify_cmd = Command::cargo_bin("relay").unwrap();
    verify_cmd
        .arg("verify")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Total Entries:    2"))
        .stdout(predicate::str::contains("VALID"));

    // 6. Query receipt list via CLI
    let mut receipt_cmd = Command::cargo_bin("relay").unwrap();
    receipt_cmd
        .arg("receipt")
        .arg("list")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("#1"))
        .stdout(predicate::str::contains("#0")); // 1 genesis + 1 write_file
}

#[tokio::test]
async fn test_rc002_upgrade_simulation_ledger_continuity() {
    let env_dir = tempdir().unwrap();
    let db_path = env_dir.path().join("upgrade_storage").join("ledger.db");

    let signer = Arc::new(Ed25519ReceiptSigner::generate("rc002-upgrade-key"));
    let pubkey_hex = hex::encode(signer.export_public_key());

    // Phase 1: Simulate v0.1.0-alpha producing entries
    {
        let mut engine = SqliteStorageEngine::open(&db_path).unwrap();
        let genesis = engine
            .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
            .unwrap();

        let mut prev_hash = genesis.entry_hash;

        for i in 1..=3 {
            let (action, action_hash) = create_test_action(&format!("v010_alpha_tool_{i}"));
            let decision = PolicyDecision::allow(
                action_hash,
                Digest::compute(b"permit(principal, action, resource);"),
                vec!["policy-01".to_string()],
            );

            let builder = ActionReceiptBuilder::new(&action, &decision)
                .with_parent_receipt_hash(prev_hash)
                .with_execution_metadata(
                    ExecutionId::new_v7(),
                    ExecutionRoute::Native,
                    "fs",
                    format!("v010_alpha_tool_{i}"),
                    action.resource.as_str(),
                    Some("GET".to_string()),
                    None,
                    Utc::now(),
                    Some(Utc::now()),
                    Some(10),
                )
                .with_observation(
                    ExecutionObservationStatus::Success,
                    0,
                    OutputHash::compute(b"{}"),
                    None,
                    2,
                    Some(200),
                    "OK",
                    false,
                    "Safe",
                    None,
                );

            let receipt = builder.build_and_sign(&signer).unwrap();
            let entry = engine.append(&receipt).unwrap();
            prev_hash = entry.entry_hash;
        }
    }

    // Phase 2: Simulate reopening with upgraded binary (RC002) and appending new entries with same persisted key
    {
        let mut engine_upgraded = SqliteStorageEngine::open(&db_path).unwrap();

        // Fetch latest entry hash to chain from
        let last_entry = engine_upgraded
            .get_by_sequence(SequenceNumber(3))
            .unwrap()
            .unwrap();
        let mut prev_hash = last_entry.entry_hash;

        for i in 4..=6 {
            let (action, action_hash) = create_test_action(&format!("v010_rc002_tool_{i}"));
            let decision = PolicyDecision::allow(
                action_hash,
                Digest::compute(b"permit(principal, action, resource);"),
                vec!["policy-01".to_string()],
            );

            let builder = ActionReceiptBuilder::new(&action, &decision)
                .with_parent_receipt_hash(prev_hash)
                .with_execution_metadata(
                    ExecutionId::new_v7(),
                    ExecutionRoute::Native,
                    "fs",
                    format!("v010_rc002_tool_{i}"),
                    action.resource.as_str(),
                    Some("GET".to_string()),
                    None,
                    Utc::now(),
                    Some(Utc::now()),
                    Some(10),
                )
                .with_observation(
                    ExecutionObservationStatus::Success,
                    0,
                    OutputHash::compute(b"{}"),
                    None,
                    2,
                    Some(200),
                    "OK",
                    false,
                    "Safe",
                    None,
                );

            let receipt = builder.build_and_sign(&signer).unwrap();
            let entry = engine_upgraded.append(&receipt).unwrap();
            prev_hash = entry.entry_hash;
        }

        // Verify complete hash chain through upgraded verification engine
        let report = LedgerVerifier::verify_file(&db_path, None, None).unwrap();
        assert!(report.status.is_valid());
        assert_eq!(report.total_verified_entries, 7); // sequence 0 through 6 = 7 entries
    }

    // Phase 3: Verify with CLI tool
    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.arg("verify")
        .arg("--ledger")
        .arg(&db_path)
        .arg("--from")
        .arg("0")
        .assert()
        .success()
        .stdout(predicate::str::contains("Total Entries:    7"))
        .stdout(predicate::str::contains("VALID"));
}

#[tokio::test]
async fn test_rc002_corrupted_ledger_detected_fail_closed() {
    let env_dir = tempdir().unwrap();
    let db_path = env_dir.path().join("corrupt_ledger.db");

    let signer = Ed25519ReceiptSigner::generate("rc002-corrupt-test-key");
    let pubkey_hex = hex::encode(signer.export_public_key());

    let mut engine = SqliteStorageEngine::open(&db_path).unwrap();
    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let mut prev_hash = genesis.entry_hash;

    for i in 1..=3 {
        let (action, action_hash) = create_test_action(&format!("tool_{i}"));
        let decision = PolicyDecision::allow(
            action_hash,
            Digest::compute(b"permit(principal, action, resource);"),
            vec!["policy-01".to_string()],
        );

        let builder = ActionReceiptBuilder::new(&action, &decision)
            .with_parent_receipt_hash(prev_hash)
            .with_execution_metadata(
                ExecutionId::new_v7(),
                ExecutionRoute::Native,
                "fs",
                format!("tool_{i}"),
                action.resource.as_str(),
                Some("GET".to_string()),
                None,
                Utc::now(),
                Some(Utc::now()),
                Some(10),
            )
            .with_observation(
                ExecutionObservationStatus::Success,
                0,
                OutputHash::compute(b"{}"),
                None,
                2,
                Some(200),
                "OK",
                false,
                "Safe",
                None,
            );

        let receipt = builder.build_and_sign(&signer).unwrap();
        let entry = engine.append(&receipt).unwrap();
        prev_hash = entry.entry_hash;
    }
    drop(engine);

    // Tamper directly with the SQLite database entry
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS prevent_receipts_update;
         UPDATE receipts SET dsse_envelope = X'DEADBEEFCAFE' WHERE sequence_number = 2;",
    )
    .unwrap();
    drop(conn);

    // Verify via CLI: must fail closed with SecurityFailure (exit code 6)
    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.arg("verify")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .failure()
        .code(ExitCode::SecurityFailure.as_i32())
        .stderr(predicate::str::contains("PayloadHashMismatch"));
}

#[test]
fn test_rc002_packaging_and_installer_script_integration() {
    let install_temp = tempdir().unwrap();
    let install_bin = install_temp.path().join("bin");

    let mut install_cmd = std::process::Command::new("bash");
    install_cmd
        .arg("install.sh")
        .current_dir(
            std::env::current_dir()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .env("INSTALL_DIR", &install_bin)
        .env("HOME", install_temp.path());

    let output = install_cmd.output().unwrap();
    assert!(
        output.status.success(),
        "install.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let installed_binary = install_bin.join("relay");
    assert!(installed_binary.exists());

    // Run doctor from installed binary
    let doctor_out = std::process::Command::new(&installed_binary)
        .arg("doctor")
        .env("HOME", install_temp.path())
        .output()
        .unwrap();

    assert!(doctor_out.status.success());
    let stdout_str = String::from_utf8_lossy(&doctor_out.stdout);
    assert!(stdout_str.contains("=== Relay System Health"));
    assert!(stdout_str.contains("Relay Version"));
}
