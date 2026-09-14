//! Ordering and Security Tests for Human Approval Subsystem (Milestone B011).
//!
//! Enforces:
//! - Strict ordering: CanonicalAction -> Cedar -> APPROVAL_REQUIRED -> Human Approval -> CredentialBroker -> Execution
//! - SI-004 / SI-006: Cryptographic ActionHash binding on approvals
//! - Fail-closed enforcement across native connectors (GitHub, Postgres)

use relay_canonical::{CanonicalAction, ToolIdentity};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, Approval, ApprovalMechanism, ApprovalState, CredentialBroker, CredentialError,
    CredentialProviderType, CredentialRequest, DecisionId, Digest, ExecutionEnvironment,
    InTotoStatement, PolicyDecision, PolicyDecisionType, PrincipalId, ResourceUri, SchemaDigest,
    SessionId,
};
use relay_receipts::{base64_decode, Ed25519ReceiptSigner};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_test_action(
    tool_name: &str,
    repo: &str,
    args: serde_json::Value,
) -> (CanonicalAction, PolicyDecision) {
    let principal = PrincipalId::new("principal:agent:test-runner").unwrap();
    let tool = ToolIdentity::new("relay", "github", tool_name);
    let full_uri = format!("github://github.com/{repo}");
    let resource = ResourceUri::parse(&full_uri).unwrap();
    let session_id = SessionId::new_v7();
    let schema_digest = SchemaDigest::compute(b"{}");
    let env = ExecutionEnvironment::current();

    let mut action = CanonicalAction {
        action_id: relay_domain::ActionId::new_v7(),
        session_id,
        principal: principal.clone(),
        mcp_method: "tools/call".to_string(),
        tool,
        resource: resource.clone(),
        canonical_arguments: args,
        schema_digest,
        environment: env,
        action_hash: ActionHash::compute(b"dummy"),
        canonical_bytes: Vec::new(),
        created_at: chrono::Utc::now(),
    };
    let computed_hash = ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
    action.action_hash = computed_hash;

    let decision = PolicyDecision {
        decision_id: DecisionId::new_v7(),
        action_hash: action.action_hash,
        policy_digest: Digest::from_bytes([0x42; 32]),
        decision: PolicyDecisionType::ApprovalRequired,
        determining_policies: vec!["policy::require_approval_for_prs".to_string()],
        reason: Some("Mutation requires human step-up authorization".to_string()),
        diagnostics: Vec::new(),
        evaluated_at: chrono::Utc::now(),
    };

    (action, decision)
}

async fn create_test_broker(token: &str) -> Arc<JitCredentialBroker> {
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("test_alias", token.as_bytes().to_vec())
        .await;
    broker.register_provider(provider).await;
    broker
}

#[tokio::test]
async fn test_ordering_credential_broker_rejects_approval_required_without_approval() {
    let broker = create_test_broker("ghp_valid_mock_token_12345").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    assert_eq!(decision.decision, PolicyDecisionType::ApprovalRequired);

    let cred_req = CredentialRequest::new(
        action.action_hash,
        action.principal.clone(),
        action.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "test_alias",
        "github",
        action.resource.as_str(),
        60,
    );

    // CRITICAL INVARIANT: CredentialBroker rejects APPROVAL_REQUIRED with CredentialError::ApprovalRequired
    let result = broker.acquire_lease(&cred_req, &decision).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        CredentialError::ApprovalRequired { action_hash } => {
            assert_eq!(action_hash, action.action_hash.to_hex());
        }
        other => panic!(
            "Expected CredentialError::ApprovalRequired, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_ordering_effective_decision_after_human_approval_permits_credential_lease() {
    let broker = create_test_broker("ghp_valid_mock_token_12345").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    let mut approval = Approval::new_with_context(
        action.action_hash,
        decision.decision_id,
        "Create PR",
        None,
        60,
        "github.create_pull_request",
        action.principal.clone(),
        action.resource.as_str(),
        decision.policy_digest,
        ApprovalMechanism::TtyInteractive,
    );

    // Human approves the request
    approval
        .approve(PrincipalId::new("principal:user:human_operator").unwrap())
        .unwrap();
    assert_eq!(approval.state, ApprovalState::Approved);

    // Derive effective decision
    let mut effective_decision = decision.clone();
    effective_decision.decision = PolicyDecisionType::Allow;

    let cred_req = CredentialRequest::new(
        action.action_hash,
        action.principal.clone(),
        action.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "test_alias",
        "github",
        action.resource.as_str(),
        60,
    );

    // Now acquire_lease succeeds
    let (lease, secret) = broker
        .acquire_lease(&cred_req, &effective_decision)
        .await
        .expect("acquire lease");

    assert_eq!(lease.action_hash, action.action_hash);
    assert_eq!(secret.as_bytes(), b"ghp_valid_mock_token_12345");
}

#[tokio::test]
async fn test_connector_blocks_on_approval_required_without_approval() {
    let broker = create_test_broker("ghp_token").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    let client = Arc::new(GitHubClient::new(GitHubClientConfig::default()).unwrap());
    let connector = GitHubConnector::new(client, "test_alias");

    // Execute with approval = None -> MUST FAIL CLOSED
    let result = connector
        .execute_governed_with_approval(&action, &decision, None, &*broker)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_connector_blocks_on_action_hash_mismatch_in_approval() {
    let broker = create_test_broker("ghp_token").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    // Approval bound to a different action hash
    let forged_hash = ActionHash::compute(b"forged_action_bytes");
    let mut approval = Approval::new_with_context(
        forged_hash,
        decision.decision_id,
        "Create PR",
        None,
        60,
        "github.create_pull_request",
        action.principal.clone(),
        action.resource.as_str(),
        decision.policy_digest,
        ApprovalMechanism::TtyInteractive,
    );
    approval
        .approve(PrincipalId::new("principal:user:human_operator").unwrap())
        .unwrap();

    let client = Arc::new(GitHubClient::new(GitHubClientConfig::default()).unwrap());
    let connector = GitHubConnector::new(client, "test_alias");

    // Execute with mismatched approval -> MUST FAIL WITH ActionHashMismatch
    let result = connector
        .execute_governed_with_approval(&action, &decision, Some(&approval), &*broker)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("ActionHash"));
}

#[tokio::test]
async fn test_connector_blocks_on_denied_approval() {
    let broker = create_test_broker("ghp_token").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    let mut approval = Approval::new_with_context(
        action.action_hash,
        decision.decision_id,
        "Create PR",
        None,
        60,
        "github.create_pull_request",
        action.principal.clone(),
        action.resource.as_str(),
        decision.policy_digest,
        ApprovalMechanism::TtyInteractive,
    );
    approval
        .deny(
            Some(PrincipalId::new("principal:user:human_operator").unwrap()),
            Some("Denied".into()),
        )
        .unwrap();

    let client = Arc::new(GitHubClient::new(GitHubClientConfig::default()).unwrap());
    let connector = GitHubConnector::new(client, "test_alias");

    let result = connector
        .execute_governed_with_approval(&action, &decision, Some(&approval), &*broker)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_connector_blocks_on_expired_approval() {
    let broker = create_test_broker("ghp_token").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    let mut approval = Approval::new_with_context(
        action.action_hash,
        decision.decision_id,
        "Create PR",
        None,
        0, // 0 second TTL
        "github.create_pull_request",
        action.principal.clone(),
        action.resource.as_str(),
        decision.policy_digest,
        ApprovalMechanism::TtyInteractive,
    );
    // Backdate expires_at
    approval.expires_at = chrono::Utc::now() - chrono::Duration::seconds(5);

    let client = Arc::new(GitHubClient::new(GitHubClientConfig::default()).unwrap());
    let connector = GitHubConnector::new(client, "test_alias");

    let result = connector
        .execute_governed_with_approval(&action, &decision, Some(&approval), &*broker)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_connector_succeeds_with_valid_approval_and_records_receipt() {
    let mock_server = MockServer::start().await;
    let broker = create_test_broker("ghp_token").await;
    let (action, decision) = create_test_action(
        "create_pull_request",
        "owner/repo",
        serde_json::json!({
            "title": "New Feature",
            "head": "feature",
            "base": "main"
        }),
    );

    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/pulls"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 1234,
            "number": 42,
            "title": "New Feature",
            "state": "open"
        })))
        .mount(&mock_server)
        .await;

    let config = GitHubClientConfig {
        base_url: mock_server.uri(),
        allow_http_loopback: true,
        ..Default::default()
    };
    let client = Arc::new(GitHubClient::new(config).unwrap());
    let connector = GitHubConnector::new(client, "test_alias");

    let mut approval = Approval::new_with_context(
        action.action_hash,
        decision.decision_id,
        "Create PR",
        None,
        60,
        "github.create_pull_request",
        action.principal.clone(),
        action.resource.as_str(),
        decision.policy_digest,
        ApprovalMechanism::TtyInteractive,
    );
    approval
        .approve(PrincipalId::new("principal:user:human_operator").unwrap())
        .unwrap();

    let signer = Ed25519ReceiptSigner::generate("test_signer");

    let result = connector
        .execute_governed_with_receipt(&action, &decision, Some(&approval), &*broker, &signer)
        .await;

    assert!(result.is_ok());
    let (exec_result, receipt) = result.unwrap();
    assert_eq!(exec_result.exit_code, 0);
    assert!(!exec_result.is_error);
    assert_eq!(receipt.action_hash, action.action_hash);

    // Verify DSSE statement contains approval evidence
    let payload_bytes = base64_decode(&receipt.dsse_envelope.payload).unwrap();
    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes).unwrap();
    assert!(statement.predicate.approval.is_some());
}
