use assert_cmd::Command;
use predicates::prelude::*;
use relay_canonical::{CanonicalAction, ToolIdentity};
use relay_domain::{
    ActionHash, ActionId, Digest, ExecutionEnvironment, ExecutionId, ExecutionObservationStatus,
    ExecutionRoute, OutputHash, PolicyDecision, PrincipalId, ReceiptSigner, ResourceUri,
    SchemaDigest, SessionId,
};
use relay_ledger::SqliteStorageEngine;
use relay_receipts::{ActionReceiptBuilder, Ed25519ReceiptSigner};
use tempfile::tempdir;

fn setup_test_ledger(
    dir: &std::path::Path,
) -> (std::path::PathBuf, Ed25519ReceiptSigner, Vec<String>) {
    let db_path = dir.join("test_cli_ledger.db");
    let mut engine = SqliteStorageEngine::open(&db_path).unwrap();

    let signer = Ed25519ReceiptSigner::generate("test-cli-signer");
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    let mut prev_hash = genesis.entry_hash;
    let mut receipt_ids = Vec::new();

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
                "github",
                format!("tool_{i}"),
                action.resource.as_str(),
                Some("GET".to_string()),
                None,
                chrono::Utc::now(),
                Some(chrono::Utc::now()),
                Some(15),
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
        receipt_ids.push(receipt.receipt_id.to_string());
        let entry = engine.append(&receipt).unwrap();
        prev_hash = entry.entry_hash;
    }

    (db_path, signer, receipt_ids)
}

fn create_test_action(tool_name: &str) -> (CanonicalAction, ActionHash) {
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-runner").unwrap();
    let tool = ToolIdentity::parse(&format!("github.{tool_name}")).unwrap();
    let resource = ResourceUri::parse("github://github.com/octocat/Hello-World").unwrap();
    let args = serde_json::json!({ "arg": tool_name });
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
        created_at: chrono::Utc::now(),
    };

    let hash = ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
    action.action_hash = hash;
    (action, hash)
}

#[test]
fn test_cli_verify_valid_ledger() {
    let dir = tempdir().unwrap();
    let (db_path, _signer, _receipt_ids) = setup_test_ledger(dir.path());

    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.args(["verify", "--db-path", db_path.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Relay Cryptographic Ledger Verification",
        ))
        .stdout(predicate::str::contains("Status:           ✓ VALID"))
        .stdout(predicate::str::contains("Total Entries:    4"))
        .stdout(predicate::str::contains("Head Sequence:    #3"));
}

#[test]
fn test_cli_verify_ledger_alias() {
    let dir = tempdir().unwrap();
    let (db_path, _signer, _receipt_ids) = setup_test_ledger(dir.path());

    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.args(["verify-ledger", "--db-path", db_path.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Status:           ✓ VALID"));
}

#[test]
fn test_cli_verify_json_output() {
    let dir = tempdir().unwrap();
    let (db_path, _signer, _receipt_ids) = setup_test_ledger(dir.path());

    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.args(["verify", "--db-path", db_path.to_str().unwrap(), "--json"]);
    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["total_verified_entries"], 4);
    assert_eq!(v["head_sequence"], 3);
    assert_eq!(v["status"], "Valid");
}

#[test]
fn test_cli_verify_tampered_fails() {
    let dir = tempdir().unwrap();
    let (db_path, _signer, _receipt_ids) = setup_test_ledger(dir.path());

    // Tamper with row in DB
    {
        let engine = SqliteStorageEngine::open(&db_path).unwrap();
        let conn = engine.raw_connection();
        conn.execute_batch("DROP TRIGGER prevent_receipts_update;")
            .unwrap();
        conn.execute(
            "UPDATE receipts SET dsse_envelope = X'DEADBEEF' WHERE sequence_number = 1",
            [],
        )
        .unwrap();
    }

    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.args(["verify", "--db-path", db_path.to_str().unwrap()]);
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("✗ FAILED: Payload hash mismatch"));
}

#[test]
fn test_cli_receipt_get_and_list() {
    let dir = tempdir().unwrap();
    let (db_path, _signer, receipt_ids) = setup_test_ledger(dir.path());

    // 1. Test receipt list
    let mut list_cmd = Command::cargo_bin("relay").unwrap();
    list_cmd.args(["receipt", "--db-path", db_path.to_str().unwrap(), "list"]);
    list_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("RECEIPT ID"))
        .stdout(predicate::str::contains(&receipt_ids[0]));

    // 2. Test receipt get
    let mut get_cmd = Command::cargo_bin("relay").unwrap();
    get_cmd.args([
        "receipt",
        "--db-path",
        db_path.to_str().unwrap(),
        "get",
        &receipt_ids[0],
    ]);
    get_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Action Receipt:"))
        .stdout(predicate::str::contains(&receipt_ids[0]))
        .stdout(predicate::str::contains("DSSE Signatures:"));
}
