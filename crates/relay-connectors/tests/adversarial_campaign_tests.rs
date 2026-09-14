//! B013 Final Adversarial Security Campaign Test Suite.
//!
//! Rigorously attacks Relay's core MVP security guarantees (G1–G8):
//! - G1: No ambient agent credentials
//! - G2: Complete mediated execution
//! - G3: Canonical integrity
//! - G4: Approval integrity
//! - G5: Credential binding
//! - G6: Evidence integrity
//! - G7: Ledger integrity
//! - G8: Fail-closed behavior

use std::sync::Arc;
use tokio::task::JoinSet;

use relay_canonical::{parse_json_strictly, ActionCanonicalizer, ToolIdentity};
use relay_connectors::coordinator::{GovernedActionError, GovernedActionRunner};
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, Approval, ApprovalMechanism, CredentialBroker, CredentialProviderType,
    CredentialRequest, DecisionId, Digest, HeadlessApprovalProvider, Ledger, PolicyDecision,
    PolicyDecisionType, PrincipalId, ReceiptSigner, ResourceUri, SequenceNumber, SessionId,
};
use relay_ledger::{LedgerVerificationStatus, LedgerVerifier, SqliteLedger, SqliteStorageEngine};
use relay_policy::CedarPolicyEngine;
use relay_receipts::{Ed25519ReceiptSigner, ReceiptVerifier};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper to spin up a fully wired test runner with in-memory persistence and keys
async fn create_adversarial_test_rig(
    cedar_policy: &str,
    approval_provider: Arc<dyn relay_domain::ApprovalProvider>,
) -> (
    Arc<GovernedActionRunner>,
    Arc<SqliteLedger>,
    Arc<Ed25519ReceiptSigner>,
    Arc<InMemoryCredentialProvider>,
    Arc<JitCredentialBroker>,
    Arc<CedarPolicyEngine>,
) {
    let engine =
        Arc::new(CedarPolicyEngine::from_str(cedar_policy, None).expect("Valid Cedar policy"));
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider.clone()).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let ledger = Arc::new(SqliteLedger::in_memory().expect("In-memory ledger"));

    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .expect("Genesis init");

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine.clone())
        .approval_provider(approval_provider)
        .credential_broker(broker.clone())
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .build()
        .expect("Runner build");

    (Arc::new(runner), ledger, signer, provider, broker, engine)
}

// =========================================================================
// 1. CANONICALIZATION ATTACKS (G3, SI-001, SI-013)
// =========================================================================

#[tokio::test]
async fn test_attack_canonicalization_duplicate_keys_rejected() {
    // Adversarial JSON payload with duplicate keys attempting parser differential
    let raw_json_with_duplicates = r#"{"path": "/safe/path.txt", "path": "/etc/shadow"}"#;

    // Strict JSON parser must reject duplicate keys to prevent parser differentials
    let result = parse_json_strictly(raw_json_with_duplicates);

    assert!(
        result.is_err(),
        "Canonicalizer parser MUST reject JSON payloads containing duplicate keys"
    );
}

#[tokio::test]
async fn test_attack_canonicalization_sql_comment_injection_prevented() {
    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.postgres.query").unwrap();

    // Attacker tries to hide destructive statements behind SQL comments
    let malicious_args = serde_json::json!({
        "host": "localhost",
        "database": "prod_db",
        "query": "SELECT id FROM users; -- DROP TABLE audit_log;"
    });

    let result = canonicalizer.canonicalize(
        session_id,
        principal,
        "tools/call",
        tool,
        &malicious_args,
        None,
        None,
    );

    assert!(
        result.is_ok(),
        "Canonicalizer strips comments and normalizes AST"
    );
    let canonical = result.unwrap();

    // Invariant: SQL AST parser detects multi-statement or comment evasion
    let canonical_query = canonical
        .canonical_arguments
        .get("query")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(
        !canonical_query.contains("DROP TABLE"),
        "Destructive injected statement must not survive canonicalization"
    );
}

// =========================================================================
// 2. AUTHORIZATION BYPASS ATTACKS (G2, SI-002, SI-003)
// =========================================================================

#[tokio::test]
async fn test_attack_authorization_unknown_action_default_deny() {
    // Policy permits safe fs read, but nothing else
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.read_file"],
            resource
        );
    "#;

    let (runner, _ledger, _signer, _provider, _broker, _engine) =
        create_adversarial_test_rig(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();

    // Attacker invents a tool: relay.system.execute_root_command
    let tool = ToolIdentity::parse("relay.system.execute_root_command").unwrap();
    let args = serde_json::json!({ "cmd": "whoami" });

    let canonical_action = canonicalizer
        .canonicalize(session_id, principal, "tools/call", tool, &args, None, None)
        .unwrap();

    let res = runner.run_action(&canonical_action).await;
    match res {
        Err(GovernedActionError::UnsupportedNamespace(ns)) => {
            // Unregistered namespace fails closed before dispatch
            assert_eq!(ns, "system");
        }
        Err(GovernedActionError::PolicyDenied { decision, .. }) => {
            assert_eq!(decision.decision, PolicyDecisionType::Deny);
            assert_eq!(decision.action_hash, canonical_action.action_hash);
        }
        Err(GovernedActionError::PolicyEvaluationFailed(_)) => {
            // Unrecognized Cedar action strictly fails closed
        }
        other => panic!("Unknown action must be strictly denied, got: {:?}", other),
    }
}

// =========================================================================
// 3. APPROVAL BYPASS ATTACKS (G4, SI-004)
// =========================================================================

#[tokio::test]
async fn test_attack_approval_action_hash_substitution_rejected() {
    // Attacker crafts Action A
    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.delete_file").unwrap();

    let args_a = serde_json::json!({ "path": "benign.txt" });
    let action_a = canonicalizer
        .canonicalize(
            session_id,
            principal.clone(),
            "tools/call",
            tool.clone(),
            &args_a,
            None,
            None,
        )
        .unwrap();

    // Attacker crafts Action B (malicious target)
    let args_b = serde_json::json!({ "path": "critical_database.db" });
    let action_b = canonicalizer
        .canonicalize(
            session_id,
            principal.clone(),
            "tools/call",
            tool.clone(),
            &args_b,
            None,
            None,
        )
        .unwrap();

    assert_ne!(action_a.action_hash, action_b.action_hash);

    // Operator approves Action A
    let mut approval = Approval::new_with_context(
        action_a.action_hash,
        DecisionId::new_v7(),
        "Approve benign.txt deletion".to_string(),
        None,
        30,
        "fs.delete_file".to_string(),
        principal.clone(),
        action_a.resource.as_str(),
        Digest::from_bytes([1u8; 32]),
        ApprovalMechanism::TtyInteractive,
    );
    approval
        .approve(PrincipalId::new("principal:operator:alice").unwrap())
        .unwrap();

    // Attacker attempts to bind approval of Action A to execute Action B
    let validation_res = approval.validate_binding(
        &action_b.action_hash,
        Some(&principal),
        Some(action_b.resource.as_str()),
        Some("fs.delete_file"),
        chrono::Utc::now(),
    );

    assert!(
        validation_res.is_err(),
        "Approval bound to Action A MUST be rejected when applied to Action B (SI-004)"
    );
}

#[tokio::test]
async fn test_attack_approval_expired_reuse_rejected() {
    let action_hash = ActionHash::compute(b"action_payload");
    let mut approval = Approval::new_with_context(
        action_hash,
        DecisionId::new_v7(),
        "Expired test".to_string(),
        None,
        0, // 0 second TTL -> expires immediately
        "fs.delete_file".to_string(),
        PrincipalId::new("principal:agent:default").unwrap(),
        "file:///test.txt",
        Digest::from_bytes([0u8; 32]),
        ApprovalMechanism::TtyInteractive,
    );

    // Ensure it is expired
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    assert!(approval.is_expired());

    // Attempt to approve expired request
    let res = approval.approve(PrincipalId::new("principal:operator:alice").unwrap());
    assert!(res.is_err(), "Cannot approve an expired approval request");
}

// =========================================================================
// 4. CREDENTIAL ATTACKS (G1, G5, SI-001, SI-006, SI-007, SI-008)
// =========================================================================

#[tokio::test]
async fn test_attack_credential_lease_action_hash_divergence_rejected() {
    let broker = JitCredentialBroker::default();
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    provider
        .add_secret("gh-secret", b"ghp_token123".to_vec())
        .await;
    broker.register_provider(provider).await;

    let legitimate_hash = ActionHash::compute(b"legitimate action");
    let forged_hash = ActionHash::compute(b"forged malicious action");

    let decision = PolicyDecision::allow(
        legitimate_hash,
        Digest::from_bytes([0u8; 32]),
        vec!["permit".to_string()],
    );

    // Attacker requests credential with forged ActionHash using legitimate decision
    let req = CredentialRequest::new(
        forged_hash,
        PrincipalId::new("principal:agent:default").unwrap(),
        ResourceUri::parse("github://github.com/org/repo").unwrap(),
        CredentialProviderType::KeyringStatic,
        "gh-secret".to_string(),
        "github",
        "github://github.com/org/repo",
        60,
    );

    let res = broker.acquire_lease(&req, &decision).await;
    assert!(
        res.is_err(),
        "CredentialBroker MUST reject lease when request ActionHash does not match PolicyDecision ActionHash (SI-006)"
    );
}

#[tokio::test]
async fn test_attack_credential_lease_replay_reuse_rejected() {
    let broker = JitCredentialBroker::default();
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    provider
        .add_secret("secret-key", b"sensitive_token".to_vec())
        .await;
    broker.register_provider(provider).await;

    let action_hash = ActionHash::compute(b"single_use_action");
    let decision = PolicyDecision::allow(
        action_hash,
        Digest::from_bytes([0u8; 32]),
        vec!["permit".to_string()],
    );

    let req = CredentialRequest::new(
        action_hash,
        PrincipalId::new("principal:agent:default").unwrap(),
        ResourceUri::parse("github://github.com/org/repo").unwrap(),
        CredentialProviderType::KeyringStatic,
        "secret-key".to_string(),
        "github",
        "github://github.com/org/repo",
        60,
    );

    // First acquisition succeeds
    let (lease, _buf) = broker
        .acquire_lease(&req, &decision)
        .await
        .expect("First lease succeeds");

    // Consume the lease upon execution completion
    broker
        .consume_lease(&lease.lease_id)
        .await
        .expect("Consume lease succeeds");

    // Replay attack: attempt to acquire or validate using consumed lease
    let second_consume = broker.consume_lease(&lease.lease_id).await;
    assert!(
        second_consume.is_err(),
        "Consumed credential lease cannot be reused or re-consumed (SI-006)"
    );
}

// =========================================================================
// 5. CONNECTOR DIRECT BYPASS ATTACKS (G2, SI-002)
// =========================================================================

#[tokio::test]
async fn test_attack_connector_direct_bypass_fails_closed() {
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path();
    let fs_connector = FilesystemConnector::new(FsConnectorConfig::new(root));

    let canonicalizer = ActionCanonicalizer::new(root.to_path_buf());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();
    let raw_args = serde_json::json!({
        "path": "bypass.txt",
        "content": "illegal direct write"
    });

    let action = canonicalizer
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

    let signer = Ed25519ReceiptSigner::default();

    // Attacker invokes connector directly with Deny decision
    let deny_decision = PolicyDecision::deny(
        action.action_hash,
        Digest::from_bytes([0u8; 32]),
        "Denied by security test".to_string(),
        vec![],
    );

    let res = fs_connector
        .execute_governed_with_receipt(&action, &deny_decision, None, &signer)
        .await;

    assert!(
        res.is_err(),
        "Connector MUST reject execution when PolicyDecision is not Allow (SI-002)"
    );
    assert!(
        !root.join("bypass.txt").exists(),
        "No file mutation may occur"
    );
}

// =========================================================================
// 6. RECEIPT FORGERY & LEDGER TAMPERING ATTACKS (G6, G7, SI-009)
// =========================================================================

#[tokio::test]
async fn test_attack_receipt_forgery_signature_tampering_detected() {
    let signer = Ed25519ReceiptSigner::default();
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    // Generate valid receipt through golden path
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": 1 })))
        .mount(&mock_server)
        .await;

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"github.get_repository"],
            resource
        );
    "#;

    let (runner, _ledger, _signer, provider, _broker, _engine) =
        create_adversarial_test_rig(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;
    provider
        .add_secret("github-pat", b"ghp_token".to_vec())
        .await;

    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = Arc::new(GitHubConnector::new(gh_client, "github-pat"));

    let runner = GovernedActionRunner::builder()
        .policy_engine(runner.policy_engine().clone())
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(runner.credential_broker().clone())
        .receipt_signer(Arc::new(Ed25519ReceiptSigner::default()))
        .ledger(runner.ledger().clone())
        .github_connector(gh_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.github.get_repository").unwrap();
    let raw_args = serde_json::json!({ "repo": "octocat/hello-world" });

    let action = canonicalizer
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

    let outcome = runner.run_action(&action).await.expect("Action succeeds");
    let mut tampered_receipt = outcome.receipt.clone();

    // Attack 1: Corrupt signature bytes
    tampered_receipt.dsse_envelope.signatures[0].sig = "bm90X2FfdmFsaWRfc2lnbmF0dXJl".to_string();
    let res1 = verifier.verify_receipt(&tampered_receipt, None, None);
    assert!(
        !res1.is_valid(),
        "Tampered signature must fail verification"
    );

    // Attack 2: Tamper with action_hash in receipt
    let mut tampered_hash_receipt = outcome.receipt.clone();
    tampered_hash_receipt.action_hash = ActionHash::compute(b"forged hash");
    let res2 = verifier.verify_receipt(&tampered_hash_receipt, None, None);
    assert!(
        !res2.is_valid(),
        "Tampered ActionHash must fail envelope hash verification"
    );
}

#[test]
fn test_attack_ledger_hash_chain_tampering_detected() {
    let mut engine = SqliteStorageEngine::in_memory().unwrap();
    let signer = Ed25519ReceiptSigner::default();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis = engine
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .unwrap();

    // Build a real canonical action and decision to construct receipt
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-runner").unwrap();
    let tool = ToolIdentity::parse("fs.read_file").unwrap();
    let resource = ResourceUri::parse("file:///test.txt").unwrap();
    let args = serde_json::json!({ "path": "/test.txt" });
    let schema_digest = relay_domain::SchemaDigest::compute(b"{}");
    let env = relay_domain::ExecutionEnvironment::current();

    let mut action = relay_canonical::CanonicalAction {
        action_id: relay_domain::ActionId::new_v7(),
        session_id,
        principal,
        mcp_method: "tools/call".to_string(),
        tool,
        resource,
        canonical_arguments: args,
        schema_digest,
        environment: env,
        action_hash: ActionHash::compute(b"placeholder"),
        canonical_bytes: Vec::new(),
        created_at: chrono::Utc::now(),
    };
    let computed_hash = ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
    action.action_hash = computed_hash;

    let decision = PolicyDecision::allow(
        computed_hash,
        Digest::compute(b"permit(principal, action, resource);"),
        vec!["policy-allow-01".to_string()],
    );

    let receipt = relay_receipts::ActionReceiptBuilder::new(&action, &decision)
        .with_parent_receipt_hash(genesis.entry_hash)
        .build_and_sign(&signer)
        .unwrap();

    let _entry = engine.append(&receipt).unwrap();

    // Verify initially valid
    let rep = LedgerVerifier::verify_connection(engine.raw_connection(), None, None).unwrap();
    assert!(rep.status.is_valid());

    // Tamper with database: drop immutability trigger and corrupt payload_hash
    let conn = engine.raw_connection_mut();
    conn.execute_batch("DROP TRIGGER prevent_ledger_update;")
        .unwrap();
    conn.execute(
        "UPDATE ledger_entries SET payload_hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE sequence_number = 1",
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

// =========================================================================
// 7. CONCURRENCY & RACE CONDITIONS (SI-006, SI-016)
// =========================================================================

#[tokio::test]
async fn test_attack_concurrent_governed_actions_zero_cross_talk() {
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path().to_path_buf();

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file"],
            resource
        );
    "#;

    let (runner, ledger, _signer, _provider, _broker, _engine) =
        create_adversarial_test_rig(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;

    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root)));
    let runner = Arc::new(
        GovernedActionRunner::builder()
            .policy_engine(runner.policy_engine().clone())
            .approval_provider(runner.approval_provider().clone())
            .credential_broker(runner.credential_broker().clone())
            .receipt_signer(runner.receipt_signer().clone())
            .ledger(ledger.clone())
            .fs_connector(fs_connector)
            .build()
            .unwrap(),
    );

    let concurrency = 20;
    let mut tasks = JoinSet::new();

    for i in 0..concurrency {
        let runner_clone = runner.clone();
        let root_clone = root.clone();
        tasks.spawn(async move {
            let canonicalizer = ActionCanonicalizer::new(root_clone);
            let session_id = SessionId::new_v7();
            let principal = PrincipalId::new("principal:agent:default").unwrap();
            let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();
            let file_name = format!("concurrent_{i}.txt");
            let raw_args = serde_json::json!({
                "path": file_name,
                "content": format!("Payload from worker {i}")
            });

            let action = canonicalizer
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

            let outcome = runner_clone
                .run_action(&action)
                .await
                .expect("Concurrent action succeeds");
            assert_eq!(outcome.action_hash, action.action_hash);
            assert_eq!(outcome.decision.action_hash, action.action_hash);
            assert_eq!(outcome.receipt.action_hash, action.action_hash);
            outcome.ledger_entry.unwrap().sequence_number.as_u64()
        });
    }

    let mut sequence_numbers = Vec::new();
    while let Some(res) = tasks.join_next().await {
        let seq = res.expect("Task join succeeds");
        sequence_numbers.push(seq);
    }

    assert_eq!(sequence_numbers.len(), concurrency);
    sequence_numbers.sort();

    // Sequences must be strictly monotonic 1..=20 with zero duplicates or gaps
    for (idx, seq) in sequence_numbers.iter().enumerate() {
        assert_eq!(
            *seq,
            (idx + 1) as u64,
            "Sequence numbers must be strictly consecutive"
        );
    }

    // Ledger hash chain must remain fully valid
    assert!(
        ledger.verify_chain().await.unwrap(),
        "Hash chain must remain valid after concurrent writes"
    );
}

// =========================================================================
// 8. CRASH / INTERRUPTION SEMANTICS MATRIX (SI-014, SI-015)
// =========================================================================

#[tokio::test]
async fn test_attack_post_execution_ledger_failure_preserves_execution_fact() {
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path().to_path_buf();
    let test_file = root.join("critical.txt");

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file"],
            resource
        );
    "#;

    let engine = Arc::new(CedarPolicyEngine::from_str(cedar_policy, None).unwrap());
    let broker = Arc::new(JitCredentialBroker::default());
    let signer = Arc::new(Ed25519ReceiptSigner::default());

    // Mock ledger that simulates disk full / write error
    struct BrokenLedger;
    #[async_trait::async_trait]
    impl Ledger for BrokenLedger {
        async fn append(
            &self,
            _receipt: &relay_domain::ActionReceipt,
        ) -> Result<relay_domain::LedgerEntry, relay_domain::LedgerError> {
            Err(relay_domain::LedgerError::WriteError(
                "ENOSPC: No space left on device".to_string(),
            ))
        }
        async fn get_by_sequence(
            &self,
            _seq: SequenceNumber,
        ) -> Result<Option<relay_domain::LedgerEntry>, relay_domain::LedgerError> {
            Ok(None)
        }
        async fn verify_chain(&self) -> Result<bool, relay_domain::LedgerError> {
            Ok(false)
        }
        async fn get_latest_receipt_hash(&self) -> Result<Digest, relay_domain::LedgerError> {
            Ok(Digest::from_bytes([0u8; 32]))
        }
    }

    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(Arc::new(BrokenLedger))
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();
    let raw_args = serde_json::json!({
        "path": "critical.txt",
        "content": "durable state mutation"
    });

    let action = canonicalizer
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

    // Run action: execution succeeds, but ledger append fails
    let outcome = runner
        .run_action(&action)
        .await
        .expect("Returns outcome with ledger_error");

    // Invariant: The execution DID happen on disk and Relay does NOT lie about it
    assert_eq!(
        std::fs::read_to_string(&test_file).unwrap(),
        "durable state mutation"
    );

    // Invariant: Outcome accurately captures that execution succeeded, receipt was created,
    // but ledger append failed with ENOSPC error
    assert_eq!(outcome.execution_result.exit_code, 0);
    assert!(outcome.ledger_entry.is_none());
    assert!(outcome.ledger_error.is_some());
    assert!(outcome.ledger_error.unwrap().contains("ENOSPC"));
}
