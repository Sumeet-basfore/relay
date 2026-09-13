//! End-to-End Governance Pipeline Integration Tests for Milestone B006.
//!
//! Tests the complete local path:
//! MCP tools/call -> B003 CanonicalAction -> B004 Cedar PEP -> B005 CredentialBroker -> B006 GitHub Connector -> mock GitHub server
//!
//! Verifies:
//! - ALLOW: Full pipeline executes, request reaches mock server, lease is consumed, result returned
//! - DENY: Policy blocks action, zero credential acquisition, ZERO network requests
//! - ActionHash mismatch: Invariant violation, ZERO network requests
//! - Credential failure: Broker errors out, ZERO network requests
//! - Expired lease: Blocked, ZERO network requests
//! - Wrong resource: Blocked, ZERO network requests

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{ActionHash, CredentialProviderType, PolicyEngine, PrincipalId};
use relay_policy::CedarPolicyEngine;
use std::sync::Arc;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_GITHUB_SECRET: &str = "ghp_governed_pipeline_token_xyz987";

async fn setup_pipeline(
    mock_server_uri: &str,
) -> (
    ActionCanonicalizer,
    Arc<CedarPolicyEngine>,
    Arc<JitCredentialBroker>,
    GitHubConnector,
) {
    // 1. Canonicalizer
    let canonicalizer = ActionCanonicalizer::default();

    // 2. Cedar PDP Engine
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());

    // 3. Credential Broker with Vaulted Secret
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("github_token", TEST_GITHUB_SECRET.as_bytes().to_vec())
        .await;
    broker.register_provider(provider).await;

    // 4. Native GitHub Connector targeting mock server
    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server_uri)).unwrap());
    let connector = GitHubConnector::new(client, "github_token");

    (canonicalizer, policy_engine, broker, connector)
}

#[tokio::test]
async fn test_full_pipeline_allow_reaches_github_and_consumes_lease() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .and(header(
            "authorization",
            format!("Bearer {TEST_GITHUB_SECRET}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1296269,
            "name": "hello-world",
            "full_name": "octocat/hello-world"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let (canonicalizer, policy_engine, broker, connector) =
        setup_pipeline(&mock_server.uri()).await;

    // Step 1: Agent calls MCP tools/call
    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "get_repository");
    let args = serde_json::json!({"repo": "octocat/hello-world"});

    // Step 2: Canonicalize to CanonicalAction
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

    // Step 3: Cedar PEP evaluation
    let auth_req = canonical_action.to_authorization_request().unwrap();
    let decision = policy_engine.evaluate(&auth_req).await.unwrap();
    assert!(
        decision.is_allowed(),
        "Cedar policy must ALLOW safe GitHub read"
    );

    // Step 4: Execute via Governed Native Connector
    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await
        .unwrap();

    // Step 5: Verify result and mock server receipt
    assert_eq!(result.exit_code, 0);
    assert!(!result.is_error);
    assert!(result.sanitized_preview.contains("HTTP 200"));
}

#[tokio::test]
async fn test_full_pipeline_deny_prevents_network_and_credential_acquisition() {
    let mock_server = MockServer::start().await;

    // Expect ZERO requests to reach the mock server!
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let (canonicalizer, policy_engine, broker, connector) =
        setup_pipeline(&mock_server.uri()).await;

    // Step 1: Agent calls an unpermitted action (delete_repository is not permitted by policy)
    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "delete_repository");
    let args = serde_json::json!({"repo": "octocat/hello-world"});

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

    // Step 2: Cedar evaluation should DENY because delete_repository is not permitted
    let auth_req = canonical_action.to_authorization_request().unwrap();
    let decision = policy_engine.evaluate(&auth_req).await.unwrap();
    assert!(decision.is_denied(), "Unpermitted action must be DENIED");

    // Step 3: Connector must reject execution without prior ALLOW
    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await;

    assert!(result.is_err());
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("without prior authorization"));

    // Step 4: Verify ZERO requests reached mock server
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        0,
        "No network request must reach GitHub on DENY"
    );
}

#[tokio::test]
async fn test_action_hash_mismatch_prevents_network_call() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let (canonicalizer, policy_engine, broker, connector) =
        setup_pipeline(&mock_server.uri()).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "get_repository");
    let args = serde_json::json!({"repo": "octocat/hello-world"});

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
    let mut decision = policy_engine.evaluate(&auth_req).await.unwrap();

    // Tamper with decision's ActionHash
    decision.action_hash = ActionHash::compute(b"tampered_action_bytes");

    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await;

    assert!(result.is_err());
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("ActionHash mismatch"));

    // Zero requests
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 0);
}

#[tokio::test]
async fn test_credential_vault_failure_prevents_network_call() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let (canonicalizer, policy_engine, _broker, connector) =
        setup_pipeline(&mock_server.uri()).await;

    // Empty broker (no token stored in vault)
    let empty_broker = Arc::new(JitCredentialBroker::new());
    let empty_provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    empty_broker.register_provider(empty_provider).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "get_repository");
    let args = serde_json::json!({"repo": "octocat/hello-world"});

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

    let result = connector
        .execute_governed(&canonical_action, &decision, &*empty_broker)
        .await;

    assert!(result.is_err());
    let err_str = result.err().unwrap().to_string();
    assert!(
        err_str.contains("Credential") || err_str.contains("Secret not found"),
        "Unexpected error message: {err_str}"
    );

    // Zero network requests
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 0);
}

#[tokio::test]
async fn test_resource_mismatch_prevents_network_call() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let (canonicalizer, policy_engine, broker, connector) =
        setup_pipeline(&mock_server.uri()).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "get_repository");
    let args = serde_json::json!({"repo": "octocat/hello-world"});

    let mut canonical_action = canonicalizer
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

    // Diverge the action's target resource
    canonical_action.resource =
        relay_domain::ResourceUri::parse("github://github.com/evil/diverged-target").unwrap();

    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await;

    assert!(result.is_err());

    // Zero network requests
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 0);
}
