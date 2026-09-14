//! B012 Golden Path End-to-End Integration Tests.
//!
//! Verifies the complete Relay execution pipeline for all 3 native connectors:
//! Raw MCP tools/call Frame
//!       ↓
//! Strict Parsing & Canonicalization
//!       ↓
//! CanonicalAction
//!       ↓
//! Cedar PEP Policy Authorization (ALLOW)
//!       ↓
//! JIT CredentialBroker Lease (Zero Long-Lived Secrets)
//!       ↓
//! Native In-Process Connector Execution (GitHub, PostgreSQL, Filesystem)
//!       ↓
//! Cryptographic ActionReceipt (Ed25519 DSSE RFC 9598 + in-toto v1.0 Statement)
//!       ↓
//! SQLite Append-Only Hash-Chain Ledger Persistence

use std::sync::Arc;

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::coordinator::{GovernedActionError, GovernedActionRunner};
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_connectors::postgres::{PostgresClient, PostgresClientConfig, PostgresConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ApprovalProvider, CredentialBroker, Ledger, PolicyEngine, PrincipalId, ReceiptSigner, SessionId,
};
use relay_ledger::SqliteLedger;
use relay_policy::CedarPolicyEngine;
use relay_receipts::{Ed25519ReceiptSigner, ReceiptVerifier};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test dummy approval provider that rejects any approval request
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

/// Helper to set up a test environment with policy engine, broker, signer, and ledger
async fn setup_test_governance(
    policy_src: &str,
) -> (
    Arc<dyn PolicyEngine>,
    Arc<dyn CredentialBroker>,
    Arc<Ed25519ReceiptSigner>,
    Arc<dyn Ledger>,
    Arc<InMemoryCredentialProvider>,
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
        .expect("Genesis initialization");

    (Arc::new(engine), broker, signer, Arc::new(ledger), provider)
}

#[tokio::test]
async fn test_e2e_golden_path_github() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1296269,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "private": false,
            "description": "This is your first repo!"
        })))
        .mount(&mock_server)
        .await;

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"github.get_repository"],
            resource
        );
    "#;

    let (engine, broker, signer, ledger, cred_store) = setup_test_governance(cedar_policy).await;

    // Seed keyring static credential for GitHub
    cred_store
        .add_secret(
            "github-pat",
            b"ghp_test_token_1234567890abcdef12345678".to_vec(),
        )
        .await;

    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = Arc::new(GitHubConnector::new(gh_client, "github-pat"));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(NeverApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .github_connector(gh_connector)
        .build()
        .expect("Runner build");

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
        .expect("Canonicalize action");

    // Execute Golden Path
    let outcome = runner
        .run_action(&canonical_action)
        .await
        .expect("Governed execution succeeds");

    // 1. Verify ActionHash consistency
    assert_eq!(outcome.action_hash, canonical_action.action_hash);
    assert_eq!(outcome.decision.action_hash, canonical_action.action_hash);
    assert_eq!(outcome.receipt.action_hash, canonical_action.action_hash);

    // 2. Verify ExecutionResult
    assert_eq!(outcome.execution_result.exit_code, 0);
    assert!(!outcome.execution_result.is_error);
    assert!(outcome
        .execution_result
        .sanitized_preview
        .contains("succeeded"));

    // 3. Verify Receipt DSSE signature and in-toto envelope
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    let verification = verifier.verify_receipt(&outcome.receipt, None, None);
    assert!(
        verification.is_valid(),
        "Receipt DSSE verification must succeed: {:?}",
        verification
    );

    // 4. Verify SQLite Ledger persistence and hash chain
    assert!(outcome.ledger_entry.is_some());
    let entry = outcome.ledger_entry.unwrap();
    assert_eq!(entry.sequence_number.as_u64(), 1);
    assert_eq!(entry.receipt_id, outcome.receipt.receipt_id);
    assert_eq!(entry.action_hash, outcome.receipt.action_hash);
    assert_eq!(entry.dsse_envelope, outcome.receipt.dsse_envelope);

    let chain_valid = ledger.verify_chain().await.expect("Chain verify");
    assert!(
        chain_valid,
        "Ledger cryptographic hash chain must be intact"
    );

    // Verify stored receipt matches generated receipt
    let fetched = ledger
        .get_by_sequence(entry.sequence_number)
        .await
        .expect("Fetch entry")
        .expect("Entry exists");
    assert_eq!(fetched.entry_hash, entry.entry_hash);
    assert_eq!(fetched.receipt_id, outcome.receipt.receipt_id);
    assert_eq!(fetched.action_hash, outcome.receipt.action_hash);
}

#[tokio::test]
async fn test_e2e_golden_path_filesystem() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let test_file = root_path.join("sandbox.txt");

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file"],
            resource
        );
    "#;

    let (engine, broker, signer, ledger, _cred_store) = setup_test_governance(cedar_policy).await;

    let fs_config = FsConnectorConfig::new(&root_path);
    let fs_connector = Arc::new(FilesystemConnector::new(fs_config));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(NeverApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .fs_connector(fs_connector)
        .build()
        .expect("Runner build");

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "sandbox.txt",
        "content": "Hello from Relay B012 Golden Path!"
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
        .expect("Canonicalize action");

    // Execute Golden Path (write_file)
    let outcome = runner
        .run_action(&canonical_action)
        .await
        .expect("Governed filesystem write succeeds");

    // Verify file content on disk
    let disk_content = std::fs::read_to_string(&test_file).expect("File was written");
    assert_eq!(disk_content, "Hello from Relay B012 Golden Path!");

    // Verify Receipt and Ledger
    assert_eq!(outcome.action_hash, canonical_action.action_hash);
    assert_eq!(outcome.execution_result.exit_code, 0);

    let verifier = ReceiptVerifier::new(signer.verifying_key());
    assert!(verifier
        .verify_receipt(&outcome.receipt, None, None)
        .is_valid());

    let chain_valid = ledger.verify_chain().await.expect("Chain verify");
    assert!(chain_valid);
}

#[tokio::test]
async fn test_e2e_golden_path_postgres() {
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"postgres.query"],
            resource
        );
    "#;

    let (engine, broker, signer, ledger, cred_store) = setup_test_governance(cedar_policy).await;

    // Seed Postgres credentials in credential provider
    cred_store
        .add_secret("postgres-creds", b"postgres:secret_db_pass".to_vec())
        .await;

    let mut cfg = PostgresClientConfig::loopback_test();
    cfg.default_port = 1; // Hermetic port: tests full pipeline through connection dispatch
    let pg_client = Arc::new(PostgresClient::new(cfg).unwrap());
    let pg_connector = Arc::new(PostgresConnector::new(pg_client, "postgres-creds"));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(NeverApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .postgres_connector(pg_connector)
        .build()
        .expect("Runner build");

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.postgres.query").unwrap();

    let raw_args = serde_json::json!({
        "host": "localhost",
        "port": 1,
        "database": "app_db",
        "query": "SELECT id, username FROM users WHERE active = true;"
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
        .expect("Canonicalize action");

    // Execute Golden Path (PostgreSQL query)
    let res = runner.run_action(&canonical_action).await;

    // Dispatched to connector, connection failed hermetically, but receipt was generated and persisted
    match res {
        Ok(outcome) => {
            assert_eq!(outcome.action_hash, canonical_action.action_hash);
            let verifier = ReceiptVerifier::new(signer.verifying_key());
            assert!(verifier
                .verify_receipt(&outcome.receipt, None, None)
                .is_valid());
            let chain_valid = ledger.verify_chain().await.expect("Chain verify");
            assert!(chain_valid);
        }
        Err(GovernedActionError::ExecutionFailed {
            error,
            receipt,
            ledger_entry,
        }) => {
            // Execution reached PostgreSQL connector and produced signed receipt of failure
            assert!(
                error.to_string().contains("Connection")
                    || error.to_string().contains("error")
                    || error.to_string().contains("failed")
            );
            assert!(
                receipt.is_some(),
                "Execution receipt must be produced even on connection failure"
            );
            assert!(
                ledger_entry.is_some(),
                "Failure receipt must be committed to ledger"
            );

            let r = receipt.unwrap();
            assert_eq!(r.action_hash, canonical_action.action_hash);

            let verifier = ReceiptVerifier::new(signer.verifying_key());
            assert!(verifier.verify_receipt(&r, None, None).is_valid());

            let chain_valid = ledger.verify_chain().await.expect("Chain verify");
            assert!(chain_valid);
        }
        Err(other) => panic!("Unexpected error variant: {:?}", other),
    }
}

#[tokio::test]
async fn test_ledger_append_failure_does_not_falsify_execution() {
    let temp_dir = TempDir::new().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let test_file = root_path.join("durable.txt");

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file"],
            resource
        );
    "#;

    let (engine, broker, signer, _ledger, _cred_store) = setup_test_governance(cedar_policy).await;

    // Create a mock ledger that always fails append
    struct FailingLedger;
    #[async_trait::async_trait]
    impl Ledger for FailingLedger {
        async fn append(
            &self,
            _receipt: &relay_domain::ActionReceipt,
        ) -> Result<relay_domain::LedgerEntry, relay_domain::LedgerError> {
            Err(relay_domain::LedgerError::WriteError(
                "Disk quota exceeded / SQLite lock error".to_string(),
            ))
        }
        async fn get_by_sequence(
            &self,
            _seq: relay_domain::SequenceNumber,
        ) -> Result<Option<relay_domain::LedgerEntry>, relay_domain::LedgerError> {
            Ok(None)
        }
        async fn verify_chain(&self) -> Result<bool, relay_domain::LedgerError> {
            Ok(false)
        }
        async fn get_latest_receipt_hash(
            &self,
        ) -> Result<relay_domain::Digest, relay_domain::LedgerError> {
            Ok(relay_domain::Digest::from_bytes([0u8; 32]))
        }
    }

    let fs_config = FsConnectorConfig::new(&root_path);
    let fs_connector = Arc::new(FilesystemConnector::new(fs_config));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(NeverApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer)
        .ledger(Arc::new(FailingLedger))
        .fs_connector(fs_connector)
        .build()
        .expect("Runner build");

    let canonicalizer = ActionCanonicalizer::new(root_path.clone());
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();

    let raw_args = serde_json::json!({
        "path": "durable.txt",
        "content": "Important side-effect payload"
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
        .expect("Canonicalize action");

    // Execute with failing ledger
    let outcome = runner
        .run_action(&canonical_action)
        .await
        .expect("Execution must return outcome and acknowledge execution happened");

    // Invariant: The execution DID happen on disk
    let content = std::fs::read_to_string(&test_file).expect("File was created");
    assert_eq!(content, "Important side-effect payload");

    // Invariant: Outcome accurately reflects that execution succeeded, receipt was generated,
    // but ledger append failed with error metadata
    assert_eq!(outcome.execution_result.exit_code, 0);
    assert!(outcome.ledger_entry.is_none());
    assert!(outcome.ledger_error.is_some());
    assert!(outcome
        .ledger_error
        .unwrap()
        .contains("Disk quota exceeded"));
}
