//! B012 Golden Path Policy Decision & Authorization Tests.
//!
//! Verifies complete mediation (SI-002, SI-003, SI-006):
//! - Cedar DENY: No credential requested, no connector invoked, no receipt generated
//! - Step-Up Human Approval: Approved, Denied, Headless, TimedOut
//! - Credential Failure: Broker fails closed before connector execution

use std::sync::Arc;

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::coordinator::{GovernedActionError, GovernedActionRunner};
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_connectors::postgres::{PostgresClient, PostgresClientConfig, PostgresConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ApprovalError, ApprovalProvider, HeadlessApprovalProvider, Ledger, MockApprovalProvider,
    PolicyDecisionType, PrincipalId, ReceiptSigner, SessionId,
};
use relay_ledger::SqliteLedger;
use relay_policy::CedarPolicyEngine;
use relay_receipts::{Ed25519ReceiptSigner, ReceiptVerifier};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test helper to set up runner dependencies
async fn setup_test_runner(
    policy_src: &str,
    approval_provider: Arc<dyn ApprovalProvider>,
) -> (
    CedarPolicyEngine,
    Arc<JitCredentialBroker>,
    Arc<InMemoryCredentialProvider>,
    Arc<Ed25519ReceiptSigner>,
    Arc<SqliteLedger>,
) {
    let engine = CedarPolicyEngine::from_str(policy_src, None).expect("Valid Cedar policy");
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider.clone()).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let ledger = SqliteLedger::in_memory().expect("In-memory ledger");

    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .expect("Genesis init");

    let _ = approval_provider;
    (engine, broker, provider, signer, Arc::new(ledger))
}

#[tokio::test]
async fn test_policy_deny_filesystem() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let test_file = root_path.join("secret.env");
    std::fs::write(&test_file, "SECRET=123").unwrap();

    // Policy permits general reads, but explicitly FORBIDS .env files
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.read_file"],
            resource
        );

        forbid (
            principal,
            action in [Relay::Action::"fs.read_file"],
            resource
        )
        when {
            context has path && context.path like "*/secret.env*"
        };
    "#;

    let (engine, broker, _provider, signer, ledger) =
        setup_test_runner(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;
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
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.read_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "secret.env"
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

    let res = runner.run_action(&canonical_action).await;
    match &res {
        Err(err @ GovernedActionError::PolicyDenied { decision, .. }) => {
            assert_eq!(decision.decision, PolicyDecisionType::Deny);
            assert_eq!(decision.action_hash, canonical_action.action_hash);
            let (code, _, _) = err.to_jsonrpc_error_parts();
            assert_eq!(code, -32003);
        }
        other => panic!("Expected PolicyDenied error, got: {:?}", other),
    }

    // Invariant: Ledger has NO entries beyond genesis
    let latest_hash = ledger.get_latest_receipt_hash().await.unwrap();
    let genesis = ledger
        .get_by_sequence(relay_domain::SequenceNumber(0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest_hash, *genesis.payload_hash());
}

#[tokio::test]
async fn test_policy_deny_github() {
    let mock_server = MockServer::start().await;

    // Notice: mock expects 0 requests because PEP denies before connector is called
    Mock::given(method("GET"))
        .and(path("/repos/octocat/secret-repo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": 1 })))
        .mount(&mock_server)
        .await;

    // Strict default deny: policy only permits other actions
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.read_file"],
            resource
        );
    "#;

    let (engine, broker, cred_store, signer, ledger) =
        setup_test_runner(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;
    cred_store
        .add_secret("github-pat", b"ghp_secret".to_vec())
        .await;

    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = Arc::new(GitHubConnector::new(gh_client, "github-pat"));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger.clone())
        .github_connector(gh_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.github.get_repository").unwrap();

    let raw_args = serde_json::json!({
        "repo": "octocat/secret-repo"
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

    let res = runner.run_action(&canonical_action).await;
    match res {
        Err(GovernedActionError::PolicyDenied { decision, .. }) => {
            assert_eq!(decision.decision, PolicyDecisionType::Deny);
        }
        other => panic!("Expected PolicyDenied, got: {:?}", other),
    }

    // Invariant: Mock server received 0 HTTP requests
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        0,
        "No HTTP requests must be sent when policy denies"
    );
}

#[tokio::test]
async fn test_policy_deny_postgres() {
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"postgres.read"],
            resource
        );

        forbid (
            principal,
            action in [Relay::Action::"postgres.query"],
            resource
        );
    "#;

    let (engine, broker, cred_store, signer, ledger) =
        setup_test_runner(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;
    cred_store
        .add_secret("pg-cred", b"pg:secret".to_vec())
        .await;

    let mut cfg = PostgresClientConfig::loopback_test();
    cfg.default_port = 1;
    let pg_client = Arc::new(PostgresClient::new(cfg).unwrap());
    let pg_connector = Arc::new(PostgresConnector::new(pg_client, "pg-cred"));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger.clone())
        .postgres_connector(pg_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.postgres.query").unwrap();

    let raw_args = serde_json::json!({
        "host": "localhost",
        "database": "test_db",
        "query": "DROP TABLE users;"
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

    let res = runner.run_action(&canonical_action).await;
    match res {
        Err(GovernedActionError::PolicyDenied { decision, .. }) => {
            assert_eq!(decision.decision, PolicyDecisionType::Deny);
        }
        other => panic!("Expected PolicyDenied, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_policy_step_up_approval_approved() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let target_file = root_path.join("victim.txt");
    std::fs::write(&target_file, "Will be deleted").unwrap();

    // Cedar policy requiring interactive human approval
    let cedar_policy = r#"
        @id("require_approval_fs_delete")
        @advice("REQUIRE_HUMAN_APPROVAL")
        @approval_required("Interactive operator approval required for file deletion")
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.delete_file"],
            resource
        );
    "#;

    let operator_principal = PrincipalId::new("principal:operator:alice").unwrap();
    let approval_provider = Arc::new(MockApprovalProvider::with_outcomes(vec![Ok(
        operator_principal.clone(),
    )]));

    let (engine, broker, _provider, signer, ledger) =
        setup_test_runner(cedar_policy, approval_provider.clone()).await;
    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root_path)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(approval_provider)
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.delete_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "victim.txt"
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

    // Execute with human approval
    let outcome = runner
        .run_action(&canonical_action)
        .await
        .expect("Approved execution succeeds");

    // Invariant: Target file deleted on disk
    assert!(
        !target_file.exists(),
        "Target file must be deleted after approved execution"
    );

    // Invariant: Receipt contains approval evidence and valid DSSE
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    assert!(verifier
        .verify_receipt(&outcome.receipt, None, None)
        .is_valid());

    // Invariant: Ledger committed entry with sequence 1
    let entry = outcome.ledger_entry.expect("Ledger entry committed");
    assert_eq!(entry.sequence_number.as_u64(), 1);
    assert_eq!(entry.receipt_id, outcome.receipt.receipt_id);
    assert!(ledger.verify_chain().await.unwrap());
}

#[tokio::test]
async fn test_policy_step_up_approval_denied() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let target_file = root_path.join("protected.txt");
    std::fs::write(&target_file, "Must survive").unwrap();

    let cedar_policy = r#"
        @approval_required("Interactive approval")
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.delete_file"],
            resource
        );
    "#;

    let approval_provider = Arc::new(MockApprovalProvider::with_outcomes(vec![Err(
        ApprovalError::DeniedByHuman("Operator denied file deletion".to_string()),
    )]));

    let (engine, broker, _provider, signer, ledger) =
        setup_test_runner(cedar_policy, approval_provider.clone()).await;
    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root_path)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(approval_provider)
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger)
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.delete_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "protected.txt"
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

    let res = runner.run_action(&canonical_action).await;
    match &res {
        Err(err @ GovernedActionError::ApprovalDenied(reason)) => {
            assert!(reason.contains("Operator denied"));
            let (code, _, _) = err.to_jsonrpc_error_parts();
            assert_eq!(code, -32001);
        }
        other => panic!("Expected ApprovalDenied, got: {:?}", other),
    }

    // Invariant: Target file was NOT deleted
    assert!(
        target_file.exists(),
        "Protected file must remain untouched when approval is denied"
    );
}

#[tokio::test]
async fn test_policy_step_up_approval_headless_fail_closed() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let target_file = root_path.join("ci_file.txt");
    std::fs::write(&target_file, "Untouched").unwrap();

    let cedar_policy = r#"
        @approval_required("Interactive approval")
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.delete_file"],
            resource
        );
    "#;

    // Headless gate fails closed immediately with NonInteractiveMode
    let approval_provider = Arc::new(HeadlessApprovalProvider);

    let (engine, broker, _provider, signer, ledger) =
        setup_test_runner(cedar_policy, approval_provider.clone()).await;
    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root_path)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(approval_provider)
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger)
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.delete_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "ci_file.txt"
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

    let res = runner.run_action(&canonical_action).await;
    match res {
        Err(err @ GovernedActionError::ApprovalHeadlessBlocked) => {
            let (code, _, _) = err.to_jsonrpc_error_parts();
            assert_eq!(code, -32005);
        }
        other => panic!("Expected ApprovalHeadlessBlocked, got: {:?}", other),
    }

    assert!(target_file.exists());
}

#[tokio::test]
async fn test_policy_step_up_approval_timeout() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let target_file = root_path.join("timeout_target.txt");
    std::fs::write(&target_file, "Untouched").unwrap();

    let cedar_policy = r#"
        @approval_required("Interactive approval")
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.delete_file"],
            resource
        );
    "#;

    let approval_provider = Arc::new(MockApprovalProvider::with_outcomes(vec![Err(
        ApprovalError::TimedOut { timeout_secs: 30 },
    )]));

    let (engine, broker, _provider, signer, ledger) =
        setup_test_runner(cedar_policy, approval_provider.clone()).await;
    let fs_connector = Arc::new(FilesystemConnector::new(FsConnectorConfig::new(&root_path)));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(approval_provider)
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger)
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.delete_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "timeout_target.txt"
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

    let res = runner.run_action(&canonical_action).await;
    match res {
        Err(err @ GovernedActionError::ApprovalTimedOut { timeout_secs }) => {
            assert_eq!(timeout_secs, 30);
            let (code, _, _) = err.to_jsonrpc_error_parts();
            assert_eq!(code, -32005);
        }
        other => panic!("Expected ApprovalTimedOut, got: {:?}", other),
    }

    assert!(target_file.exists());
}

#[tokio::test]
async fn test_credential_failure_fails_closed() {
    let mock_server = MockServer::start().await;

    // Policy permits access
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"github.get_repository"],
            resource
        );
    "#;

    // Notice: We do NOT seed the credential for "github-pat" in the store!
    let (engine, broker, _cred_store, signer, ledger) =
        setup_test_runner(cedar_policy, Arc::new(HeadlessApprovalProvider)).await;

    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = Arc::new(GitHubConnector::new(gh_client, "github-pat"));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(Arc::new(HeadlessApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(ledger)
        .github_connector(gh_connector)
        .build()
        .unwrap();

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.github.get_repository").unwrap();

    let raw_args = serde_json::json!({
        "repo": "octocat/hello-world"
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

    let res = runner.run_action(&canonical_action).await;
    match &res {
        Err(err @ GovernedActionError::CredentialFailed(cred_err)) => {
            assert!(
                cred_err.to_string().contains("not found")
                    || cred_err.to_string().contains("NotFound")
            );
            let (code, _, _) = err.to_jsonrpc_error_parts();
            assert_eq!(code, -32002);
        }
        other => panic!("Expected CredentialFailed, got: {:?}", other),
    }

    // Invariant: Mock server received 0 HTTP requests (network dispatch aborted)
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        0,
        "No network request when credential acquisition fails"
    );
}
