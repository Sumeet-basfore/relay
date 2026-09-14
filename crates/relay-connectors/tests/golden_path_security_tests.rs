//! B012 Golden Path Security, Integrity, and Secret Boundary Tests.
//!
//! Enforces:
//! - SI-001 / SI-010: Cryptographic ActionHash consistency across all 7 lifecycle stages
//! - SI-002 / SI-006: Direct connector call protection (complete mediation)
//! - SI-005: Canonical resource consistency across policy, connector, and receipt
//! - SI-009 / SI-012: Zero secret leakage in receipts, ledger, previews, or diagnostics

use std::sync::Arc;

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::coordinator::GovernedActionRunner;
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, ExecutionError, HeadlessApprovalProvider, InTotoStatement, Ledger, PolicyDecision,
    PolicyDecisionType, PrincipalId, ReceiptSigner, SessionId,
};
use relay_ledger::SqliteLedger;
use relay_policy::CedarPolicyEngine;
use relay_receipts::{base64_decode, Ed25519ReceiptSigner};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CANARY_SECRET: &str = "ghp_CANARY_SECRET_TOKEN_9876543210_RELAY_TOP_SECRET";

#[tokio::test]
async fn test_action_hash_consistency_across_all_seven_stages() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1296269,
            "name": "hello-world",
            "full_name": "octocat/hello-world"
        })))
        .mount(&mock_server)
        .await;

    let cedar_policy = r#"
        @approval_required("Require signoff")
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"github.get_repository"],
            resource
        );
    "#;

    let engine = CedarPolicyEngine::from_str(cedar_policy, None).expect("Valid policy");
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    provider
        .add_secret("github-pat", b"ghp_valid_token_12345".to_vec())
        .await;

    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let ledger = SqliteLedger::in_memory().expect("In-memory ledger");

    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .expect("Genesis init");

    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = Arc::new(GitHubConnector::new(gh_client, "github-pat"));

    let approval_provider = Arc::new(relay_domain::MockApprovalProvider::with_outcomes(vec![Ok(
        PrincipalId::new("principal:operator:alice").unwrap(),
    )]));

    let runner = GovernedActionRunner::builder()
        .policy_engine(Arc::new(engine))
        .approval_provider(approval_provider)
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(Arc::new(ledger))
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

    // Stage 1: Canonicalization produces authoritative ActionHash
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
    let original_hash = canonical_action.action_hash;

    // Execute through Golden Path
    let outcome = runner
        .run_action(&canonical_action)
        .await
        .expect("Execution succeeds");

    // Stage 2: Policy Decision ActionHash binding
    assert_eq!(outcome.decision.action_hash, original_hash);

    // Stage 3: Operator Approval ActionHash binding
    let approval = outcome.approval.expect("Approval evidence must be present");
    assert_eq!(approval.action_hash, original_hash);

    // Stage 4: Execution Outcome ActionHash binding
    assert_eq!(outcome.action_hash, original_hash);

    // Stage 5 & 6: ActionReceipt & in-toto Statement Subject ActionHash binding
    assert_eq!(outcome.receipt.action_hash, original_hash);
    let statement_bytes = base64_decode(&outcome.receipt.dsse_envelope.payload)
        .expect("Valid base64 statement payload");
    let in_toto_statement: InTotoStatement =
        serde_json::from_slice(&statement_bytes).expect("Valid in-toto statement JSON");
    assert_eq!(in_toto_statement.subject.len(), 1);
    assert_eq!(
        in_toto_statement.subject[0].digest.get("sha256").unwrap(),
        &original_hash.to_hex()
    );
    assert_eq!(in_toto_statement.predicate.action_hash, original_hash);

    // Stage 7: Ledger Entry ActionHash binding
    let ledger_entry = outcome.ledger_entry.expect("Ledger entry committed");
    assert_eq!(ledger_entry.action_hash, original_hash);
}

#[tokio::test]
async fn test_action_tampering_at_execution_boundary_rejected() {
    let mock_server = MockServer::start().await;

    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"github.get_repository"],
            resource
        );
    "#;

    let engine = CedarPolicyEngine::from_str(cedar_policy, None).expect("Valid policy");
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    provider
        .add_secret("github-pat", b"ghp_valid".to_vec())
        .await;

    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = Arc::new(GitHubConnector::new(gh_client, "github-pat"));

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
            principal.clone(),
            "tools/call",
            tool,
            &raw_args,
            None,
            None,
        )
        .unwrap();

    // Fabricate a decision with a divergent ActionHash (tampering attack)
    let fake_hash = ActionHash::compute(b"malicious tampered payload");
    let fake_decision = PolicyDecision {
        decision_id: relay_domain::DecisionId::new_v7(),
        action_hash: fake_hash,
        decision: PolicyDecisionType::Allow,
        policy_digest: engine.policy_digest(),
        determining_policies: vec!["permit".to_string()],
        diagnostics: Vec::new(),
        evaluated_at: chrono::Utc::now(),
        reason: None,
    };

    // Calling connector directly with mismatched decision ActionHash MUST fail closed (SI-005, SI-006)
    let res = gh_connector
        .execute_governed_with_receipt(
            &canonical_action,
            &fake_decision,
            None,
            broker.as_ref(),
            &signer,
        )
        .await;

    match res {
        Err((ExecutionError::ConnectorFailed { reason, .. }, None)) => {
            assert!(
                reason.contains("ActionHash")
                    || reason.contains("divergence")
                    || reason.contains("mismatch")
            );
        }
        other => panic!(
            "Expected ConnectorFailed with ActionHash mismatch, got: {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_connector_direct_call_protection_fails_closed() {
    let mock_server = MockServer::start().await;

    let client_config = GitHubClientConfig::loopback_test(mock_server.uri());
    let gh_client = Arc::new(GitHubClient::new(client_config).unwrap());
    let gh_connector = GitHubConnector::new(gh_client, "github-pat");

    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider).await;
    let signer = Ed25519ReceiptSigner::default();

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.github.get_repository").unwrap();

    let raw_args = serde_json::json!({ "repo": "octocat/hello-world" });
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

    // Attack 1: Call connector with PolicyDecision::Deny
    let deny_decision = PolicyDecision {
        decision_id: relay_domain::DecisionId::new_v7(),
        action_hash: canonical_action.action_hash,
        decision: PolicyDecisionType::Deny,
        policy_digest: relay_domain::Digest::from_bytes([0u8; 32]),
        determining_policies: vec![],
        diagnostics: Vec::new(),
        evaluated_at: chrono::Utc::now(),
        reason: Some("Denied".to_string()),
    };

    let res1 = gh_connector
        .execute_governed_with_receipt(
            &canonical_action,
            &deny_decision,
            None,
            broker.as_ref(),
            &signer,
        )
        .await;
    assert!(
        res1.is_err(),
        "Direct invocation with PolicyDecision::Deny must be rejected"
    );

    // Attack 2: Call connector with PolicyDecision::ApprovalRequired but without approval evidence
    let req_approval_decision = PolicyDecision {
        decision_id: relay_domain::DecisionId::new_v7(),
        action_hash: canonical_action.action_hash,
        decision: PolicyDecisionType::ApprovalRequired,
        policy_digest: relay_domain::Digest::from_bytes([0u8; 32]),
        determining_policies: vec![],
        diagnostics: Vec::new(),
        evaluated_at: chrono::Utc::now(),
        reason: None,
    };

    let res2 = gh_connector
        .execute_governed_with_receipt(
            &canonical_action,
            &req_approval_decision,
            None,
            broker.as_ref(),
            &signer,
        )
        .await;
    assert!(
        res2.is_err(),
        "Direct invocation requiring approval without approval evidence must be rejected"
    );
}

#[tokio::test]
async fn test_secret_boundary_canary_zero_leakage() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1296269,
            "name": "hello-world",
            "full_name": "octocat/hello-world"
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

    let engine = CedarPolicyEngine::from_str(cedar_policy, None).expect("Valid policy");
    let provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    // Seed HIGH-ENTROPY CANARY SECRET
    provider
        .add_secret("github-pat", CANARY_SECRET.as_bytes().to_vec())
        .await;

    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(provider).await;
    let signer = Arc::new(Ed25519ReceiptSigner::default());
    let ledger = Arc::new(SqliteLedger::in_memory().expect("In-memory ledger"));

    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .expect("Genesis init");

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

    let outcome = runner
        .run_action(&canonical_action)
        .await
        .expect("Execution succeeds");

    // 1. Check ExecutionResult stdout, stderr, preview
    assert!(
        !outcome
            .execution_result
            .stdout_digest
            .to_hex()
            .contains(CANARY_SECRET),
        "Canary secret must not appear in stdout digest"
    );
    assert!(
        !outcome
            .execution_result
            .sanitized_preview
            .contains(CANARY_SECRET),
        "Canary secret must not appear in sanitized preview"
    );

    // 2. Check ActionReceipt JSON serialization
    let receipt_json = serde_json::to_string(&outcome.receipt).unwrap();
    assert!(
        !receipt_json.contains(CANARY_SECRET),
        "Canary secret must NEVER leak into ActionReceipt JSON"
    );

    // 3. Check Decoded in-toto Statement
    let statement_bytes = base64_decode(&outcome.receipt.dsse_envelope.payload)
        .expect("Valid base64 statement payload");
    let statement_str = String::from_utf8(statement_bytes).expect("Valid UTF-8 statement");
    assert!(
        !statement_str.contains(CANARY_SECRET),
        "Canary secret must NEVER leak into in-toto Statement JSON"
    );

    // 4. Check SQLite Ledger stored payload & entries
    let entry = outcome.ledger_entry.expect("Ledger entry committed");
    let entry_json = serde_json::to_string(&entry).unwrap();
    assert!(
        !entry_json.contains(CANARY_SECRET),
        "Canary secret must NEVER leak into Ledger entry representation"
    );

    let fetched = ledger
        .get_by_sequence(entry.sequence_number)
        .await
        .unwrap()
        .unwrap();
    let fetched_json = serde_json::to_string(&fetched).unwrap();
    assert!(
        !fetched_json.contains(CANARY_SECRET),
        "Canary secret must NEVER leak into persisted SQLite Ledger records"
    );
}
