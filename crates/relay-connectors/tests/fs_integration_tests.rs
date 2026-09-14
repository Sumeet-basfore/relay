//! End-to-end integration tests for Filesystem connector under complete Relay governance (B010).
//!
//! Pipeline:
//! MCP tools/call
//!   ↓
//! CanonicalAction (B003 path normalization & ActionHash)
//!   ↓
//! Cedar PEP (B004 strict default deny, policy digest)
//!   ↓
//! FilesystemConnector::execute_governed_with_receipt (B010 root jail, physical execution)
//!   ↓
//! Ed25519 DSSE ActionReceipt (B007)
//!   ↓
//! SqliteLedger (B008 append-only hash chain)

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_domain::{Ledger, PolicyEngine, PrincipalId, ReceiptSigner};
use relay_ledger::SqliteLedger;
use relay_policy::CedarPolicyEngine;
use relay_receipts::{Ed25519ReceiptSigner, ReceiptVerifier};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_pipeline_fs_read_allowed_with_receipt_and_ledger() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();

    // Create safe file inside root
    let target_file = root.join("hello.txt");
    std::fs::write(&target_file, b"Relay Filesystem Governance").unwrap();

    let cfg = FsConnectorConfig::new(&root);
    let connector = FilesystemConnector::new(cfg);
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());
    let canonicalizer = ActionCanonicalizer::default();
    let signer = Ed25519ReceiptSigner::generate("relay-test-signer");

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:worker").unwrap();
    let tool_ident = ToolIdentity::new("relay", "fs", "read_file");
    let args = serde_json::json!({
        "path": target_file.to_string_lossy().to_string(),
    });

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

    // Evaluate Cedar policy
    let auth_req = canonical_action.to_authorization_request().unwrap();
    let decision = policy_engine.evaluate(&auth_req).await.unwrap();
    assert!(decision.is_allowed());

    // Governed execution with cryptographic receipt
    let (exec_res, receipt) = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &signer)
        .await
        .expect("governed read");

    assert_eq!(exec_res.exit_code, 0);
    assert!(!exec_res.is_error);

    // Verify receipt independently
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    assert!(verifier
        .verify_receipt(
            &receipt,
            Some(&canonical_action.action_hash),
            Some(&decision.policy_digest)
        )
        .is_valid());

    // Append to SQLite ledger
    let ledger = SqliteLedger::in_memory().unwrap();
    let pubkey_bytes: [u8; 32] = signer.export_public_key().try_into().unwrap();
    let pubkey_hex = hex::encode(pubkey_bytes);
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    ledger.append(&receipt).await.unwrap();
    assert!(ledger.verify_chain().await.unwrap());
}

#[tokio::test]
async fn test_full_pipeline_fs_sensitive_env_file_forbidden_by_policy() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();

    let env_file = root.join(".env");
    std::fs::write(&env_file, b"SECRET_API_KEY=supersecret").unwrap();

    let cfg = FsConnectorConfig::new(&root);
    let connector = FilesystemConnector::new(cfg);
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());
    let canonicalizer = ActionCanonicalizer::default();

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:worker").unwrap();
    let tool_ident = ToolIdentity::new("relay", "fs", "read_file");
    let args = serde_json::json!({
        "path": env_file.to_string_lossy().to_string(),
    });

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
    assert!(decision.is_denied());

    // Connector execution must fail closed
    let result = connector
        .execute_governed(&canonical_action, &decision)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_full_pipeline_fs_delete_requires_approval() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();

    let file_to_delete = root.join("delete_me.txt");
    std::fs::write(&file_to_delete, b"data").unwrap();

    let cfg = FsConnectorConfig::new(&root);
    let connector = FilesystemConnector::new(cfg);
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());
    let canonicalizer = ActionCanonicalizer::default();
    let signer = Ed25519ReceiptSigner::generate("relay-test-signer");

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:worker").unwrap();
    let tool_ident = ToolIdentity::new("relay", "fs", "delete_file");
    let args = serde_json::json!({
        "path": file_to_delete.to_string_lossy().to_string(),
    });

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
    assert!(!decision.is_allowed());
    assert!(decision.requires_approval());

    // Attempting execution without approval must fail closed
    let unapproved_res = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &signer)
        .await;
    assert!(unapproved_res.is_err());
    // When approval is required, passing None for approval is rejected or fails
    // In our policy, let's create a valid approval
    let mut approval = relay_domain::Approval::new(
        canonical_action.action_hash,
        decision.decision_id,
        "Delete file request",
        None,
        300,
    );
    let approver_principal = PrincipalId::new("principal:human:security_admin").unwrap();
    approval
        .approve(approver_principal)
        .expect("valid approval");

    let (exec_res, receipt) = connector
        .execute_governed_with_receipt(&canonical_action, &decision, Some(&approval), &signer)
        .await
        .expect("approved deletion");

    assert_eq!(exec_res.exit_code, 0);
    assert!(!file_to_delete.exists());

    // Verify DSSE statement contains approval
    let payload_bytes =
        relay_receipts::base64_decode(&receipt.dsse_envelope.payload).expect("decode payload");
    let statement: relay_domain::InTotoStatement =
        serde_json::from_slice(&payload_bytes).expect("parse statement");
    assert!(statement.predicate.approval.is_some());
}
