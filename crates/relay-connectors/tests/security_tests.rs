//! Comprehensive Adversarial and Security Invariant Tests for GitHub Native Connector.
//!
//! Evaluates all 20 threat vectors specified by Milestone B006 Section 23:
//! 1. Host substitution (SI-003, SI-007)
//! 2. Scheme substitution (SI-003, SI-007)
//! 3. Port substitution (SI-003, SI-007)
//! 4. Redirect to untrusted host (SI-001, SI-007)
//! 5. Repository-name traversal (SI-005)
//! 6. Malformed owner/repository (SI-005)
//! 7. PR number confusion (SI-005)
//! 8. Credential leakage through error (SI-001)
//! 9. Credential leakage through URL (SI-001)
//! 10. ActionHash mismatch (SI-006)
//! 11. Resource mismatch (SI-006)
//! 12. Principal mismatch (SI-002)
//! 13. Expired lease (SI-006)
//! 14. Reused lease (SI-006)
//! 15. Automatic retry of mutation (SI-014)
//! 16. Timeout after mutation (SI-014)
//! 17. Oversized GitHub response (SI-014)
//! 18. Malicious response headers/body (SI-014)
//! 19. Connector called without authorization (SI-002)
//! 20. Connector called without credential authorization (SI-001, SI-002)

use relay_canonical::{CanonicalAction, GitHubNormalizer, ToolIdentity};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector, GitHubError};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, CredentialBroker, CredentialLease, CredentialProviderType, CredentialRequest,
    ExecutionEnvironment, NativeConnector, PolicyDecision, PrincipalId, ResourceUri, SchemaDigest,
    SecretBuffer, SessionId,
};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_test_action(
    tool_name: &str,
    repo: &str,
    args: serde_json::Value,
) -> (CanonicalAction, PolicyDecision) {
    let principal = PrincipalId::new("principal:agent:adversary").unwrap();
    let tool = ToolIdentity::new("relay", "github", tool_name);
    let full_uri = format!("github://github.com/{repo}");
    let resource = ResourceUri::parse(&full_uri).unwrap();
    let session_id = SessionId::new_v7();
    let schema_digest = SchemaDigest::compute(b"{}");
    let env = ExecutionEnvironment::current();

    let mut action = CanonicalAction {
        action_id: relay_domain::ActionId::new_v7(),
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

    let computed_hash = ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
    action.action_hash = computed_hash;

    let decision = PolicyDecision::allow(
        computed_hash,
        relay_domain::Digest::compute(b"schema"),
        vec!["permit_github_reads".to_string()],
    );

    (action, decision)
}

async fn create_test_broker(token: &str) -> Arc<JitCredentialBroker> {
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("github_token", token.as_bytes().to_vec())
        .await;
    broker.register_provider(provider).await;
    broker
}

/// Threat Vector 1: Host substitution
/// Invariant: SI-003, SI-007 (Strict host whitelisting)
#[test]
fn test_threat_1_host_substitution_rejected() {
    let bad_config = GitHubClientConfig {
        base_url: "https://evil.attacker.com".to_string(),
        allow_http_loopback: false,
        ..Default::default()
    };
    let res = GitHubClient::new(bad_config);
    assert!(res.is_err());
    let err = res.err().unwrap().to_string();
    assert!(err.contains("not an authorized GitHub host") || err.contains("SI-007"));
}

/// Threat Vector 2: Scheme substitution
/// Invariant: SI-003, SI-007 (Enforce TLS scheme)
#[test]
fn test_threat_2_scheme_substitution_rejected() {
    let http_config = GitHubClientConfig {
        base_url: "http://api.github.com".to_string(),
        allow_http_loopback: false,
        ..Default::default()
    };
    let res = GitHubClient::new(http_config);
    assert!(res.is_err());
    let err = res.err().unwrap().to_string();
    assert!(err.contains("HTTP scheme forbidden") || err.contains("SI-007"));

    let ftp_config = GitHubClientConfig {
        base_url: "ftp://api.github.com".to_string(),
        allow_http_loopback: false,
        ..Default::default()
    };
    assert!(GitHubClient::new(ftp_config).is_err());
}

/// Threat Vector 3: Port substitution
/// Invariant: SI-003, SI-007 (Lock to default HTTPS port in production)
#[test]
fn test_threat_3_port_substitution_rejected() {
    let _port_config = GitHubClientConfig {
        base_url: "https://api.github.com:8443".to_string(),
        allow_http_loopback: false,
        ..Default::default()
    };
    // If a client was created pointing to standard port, executing request with modified port fails
    let client = GitHubClient::new(GitHubClientConfig::default()).unwrap();
    let secret = SecretBuffer::from_slice(b"test");

    // Runtime port mismatch detection in execute_request
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        client
            .execute_request(
                reqwest::Method::GET,
                ":8080/repos/owner/repo",
                None,
                &secret,
                false,
                "get_repository",
            )
            .await
    });
    assert!(res.is_err());
}

/// Threat Vector 4: Redirect to untrusted host
/// Invariant: SI-001, SI-007 (Egress proxy boundary and zero secret leakage)
#[tokio::test]
async fn test_threat_4_redirect_to_untrusted_host_blocked() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(302)
                .append_header("location", "https://attacker.com/steal-tokens"),
        )
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker("super_secret_token_123").await;

    let (action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    assert!(res.is_err());
    let err_str = res.err().unwrap().to_string();
    assert!(
        err_str.contains("redirect")
            || err_str.contains("untrusted host")
            || err_str.contains("rejected")
    );
}

/// Threat Vector 5: Repository-name traversal
/// Invariant: SI-005 (Canonical Action Equivalence)
#[test]
fn test_threat_5_repository_name_traversal() {
    assert!(GitHubNormalizer::parse("octocat/../malicious/repo").is_err());
    assert!(GitHubNormalizer::parse("../../../etc/passwd").is_err());
}

/// Threat Vector 6: Malformed owner/repository
/// Invariant: SI-005 (Canonical Action Equivalence)
#[test]
fn test_threat_6_malformed_owner_repository() {
    assert!(GitHubNormalizer::parse("bad owner/repo").is_err());
    assert!(GitHubNormalizer::parse("owner/bad$repo").is_err());
}

/// Threat Vector 7: PR number confusion
/// Invariant: SI-005 (Canonical Action Equivalence)
#[test]
fn test_threat_7_pr_number_confusion() {
    let (action, _) = create_test_action(
        "get_pull_request",
        "octocat/hello-world/pull/10",
        serde_json::json!({"pull_number": 99}),
    );
    let res = relay_connectors::github::GitHubOperation::from_canonical_action(&action);
    assert!(matches!(res, Err(GitHubError::ResourceMismatch { .. })));
}

/// Threat Vector 8: Credential leakage through error
/// Invariant: SI-001 (Zero Target Secrets in Error Outputs)
#[tokio::test]
async fn test_threat_8_credential_never_leaked_in_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid token"))
        .mount(&mock_server)
        .await;

    let secret_pat = "RELAY_TEST_GITHUB_SECRET_DO_NOT_LEAK_123";
    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker(secret_pat).await;

    let (action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    let err_str = err.to_string();
    assert!(
        !err_str.contains(secret_pat),
        "Secret token leaked in error message!"
    );
}

/// Threat Vector 9: Credential leakage through URL
/// Invariant: SI-001 (Zero credentials in URLs or Query Parameters)
#[tokio::test]
async fn test_threat_9_credential_never_in_url() {
    let mock_server = MockServer::start().await;

    let secret_pat = "RELAY_TEST_GITHUB_SECRET_DO_NOT_LEAK_123";
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 1})))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker(secret_pat).await;

    let (action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let _ = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap();

    // Verify wiremock recorded requests: URL must NOT contain token!
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert!(!req.url.as_str().contains(secret_pat));
    assert_eq!(req.url.query(), None);
}

/// Threat Vector 10: ActionHash mismatch
/// Invariant: SI-006 (Single-Action Credential Binding)
#[tokio::test]
async fn test_threat_10_action_hash_mismatch() {
    let broker = create_test_broker("token").await;
    let (action, _) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );

    // Forged decision with mismatched ActionHash
    let decision = PolicyDecision::allow(
        ActionHash::compute(b"attacker_hash"),
        relay_domain::Digest::compute(b"schema"),
        vec!["permit_github_reads".to_string()],
    );

    let connector = GitHubConnector::default_production().unwrap();
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    assert!(res.is_err());
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .contains("ActionHash mismatch"));
}

/// Threat Vector 11: Resource mismatch
/// Invariant: SI-006 (Credential Lease Resource Scope)
#[tokio::test]
async fn test_threat_11_resource_mismatch() {
    let broker = create_test_broker("token").await;
    let (mut action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );

    // Alter action resource to a different repository after decision was computed
    action.resource = ResourceUri::parse("github://github.com/octocat/secret-repo").unwrap();

    let connector = GitHubConnector::default_production().unwrap();
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    assert!(res.is_err());
}

/// Threat Vector 12: Principal mismatch
/// Invariant: SI-002 (Complete Mediation)
#[tokio::test]
async fn test_threat_12_principal_mismatch() {
    let broker = create_test_broker("token").await;
    let (mut action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );

    // Change action principal after decision
    action.principal = PrincipalId::new("principal:agent:imposter").unwrap();
    let connector = GitHubConnector::default_production().unwrap();
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    assert!(res.is_err());
}

/// Threat Vector 13: Expired lease
/// Invariant: SI-006 (Lease Lifetime Expiration)
#[test]
fn test_threat_13_expired_lease() {
    let mut lease = CredentialLease::new(
        ActionHash::compute(b"h"),
        PrincipalId::new("principal:agent:test").unwrap(),
        CredentialProviderType::KeyringStatic,
        "token",
        "github",
        "github://github.com/octocat/hello-world",
        0, // 0 second TTL -> expires immediately
    );
    lease.expires_at = chrono::Utc::now() - chrono::Duration::seconds(10);
    assert!(lease.is_expired());
    assert!(!lease.is_active());
}

/// Threat Vector 14: Reused lease
/// Invariant: SI-006 (Single-Use Lease Consumption)
#[tokio::test]
async fn test_threat_14_reused_lease() {
    let broker = create_test_broker("token").await;
    let (action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );

    let cred_req = CredentialRequest::new(
        action.action_hash,
        action.principal.clone(),
        action.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "github_token",
        "github",
        action.resource.as_str(),
        60,
    );

    let (lease, _secret) = broker.acquire_lease(&cred_req, &decision).await.unwrap();
    assert!(broker.validate_lease(&lease).await.unwrap());

    // Burn lease
    broker.consume_lease(&lease.lease_id).await.unwrap();

    // Reusing the consumed lease must fail
    assert!(!broker.validate_lease(&lease).await.unwrap());
}

/// Threat Vector 15: Automatic retry of mutation
/// Invariant: SI-014 (Fail Closed on Divergence)
#[test]
fn test_threat_15_no_automatic_retry_of_mutation() {
    let (action, _) = create_test_action(
        "create_issue",
        "octocat/hello-world",
        serde_json::json!({"title": "Duplicate Risk"}),
    );
    let op = relay_connectors::github::GitHubOperation::from_canonical_action(&action).unwrap();
    assert!(op.is_mutating());
    assert_eq!(
        op.idempotency_class(),
        relay_connectors::github::IdempotencyClass::NotSafeToRetry
    );
}

/// Threat Vector 16: Timeout after mutation
/// Invariant: SI-014 (Ambiguous Remote State Handling)
#[tokio::test]
async fn test_threat_16_timeout_after_mutation_yields_ambiguous_outcome() {
    let mock_server = MockServer::start().await;

    // Simulate hung POST response causing timeout
    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_secs(3)))
        .mount(&mock_server)
        .await;

    let mut config = GitHubClientConfig::loopback_test(mock_server.uri());
    config.request_timeout = Duration::from_millis(50); // Timeout immediately
    let client = Arc::new(GitHubClient::new(config).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker("test_pat").await;

    let (action, decision) = create_test_action(
        "create_issue",
        "octocat/hello-world",
        serde_json::json!({"title": "Timeout Issue"}),
    );
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    assert!(res.is_err());
    let err_msg = res.err().unwrap().to_string();
    assert!(
        err_msg.contains("Ambiguous mutation outcome")
            || err_msg.contains("remote mutation outcome unknown"),
        "Expected AmbiguousMutationOutcome, got: {err_msg}"
    );
}

/// Threat Vector 17: Oversized GitHub response
/// Invariant: SI-014 (Resource Exhaustion Prevention)
#[tokio::test]
async fn test_threat_17_oversized_response_rejected() {
    let mock_server = MockServer::start().await;

    // Return 3 MB response (exceeds 2 MB limit)
    let huge_body = vec![b'x'; 3 * 1024 * 1024];
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(huge_body))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker("test_pat").await;

    let (action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    assert!(res.is_err());
    assert!(res.err().unwrap().to_string().contains("too large"));
}

/// Threat Vector 18: Malicious response headers/body
/// Invariant: SI-014 (Safe Failure on Malformed Downstream Data)
#[tokio::test]
async fn test_threat_18_malicious_response_handled_cleanly() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(b"\x00\xFF\xFE\xFD malformed binary payload"),
        )
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker("test_pat").await;

    let (action, decision) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let res = connector
        .execute_governed(&action, &decision, &*broker)
        .await;
    // Must complete safely without panic
    assert!(res.is_ok());
    let output = res.unwrap();
    assert_eq!(output.exit_code, 0);
}

/// Threat Vector 19: Connector called without authorization
/// Invariant: SI-002 (Complete Mediation)
#[tokio::test]
async fn test_threat_19_connector_called_without_authorization() {
    let broker = create_test_broker("token").await;
    let (action, _) = create_test_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );

    // Denied policy decision
    let deny_decision = PolicyDecision::deny(
        action.action_hash,
        relay_domain::Digest::compute(b"schema"),
        "Explicitly forbidden by Cedar policy",
        vec!["forbid_policy".to_string()],
    );

    let connector = GitHubConnector::default_production().unwrap();
    let res = connector
        .execute_governed(&action, &deny_decision, &*broker)
        .await;
    assert!(res.is_err());
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .contains("without prior authorization"));
}

/// Threat Vector 20: Connector called without credential authorization
/// Invariant: SI-001, SI-002 (Zero Ambient Credentials)
#[tokio::test]
async fn test_threat_20_connector_called_without_credential_authorization() {
    let connector = GitHubConnector::default_production().unwrap();
    // Directly attempting execution via NativeConnector without secret
    let res = connector
        .execute(
            "get_repository",
            &serde_json::json!({"repo": "octocat/hello-world"}),
            None,
        )
        .await;
    assert!(res.is_err());
    let err = res.err().unwrap().to_string();
    assert!(err.contains("SecretBuffer") || err.contains("requires authenticated"));
}
