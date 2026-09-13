//! End-to-End Governance Pipeline with Cryptographic Action Receipts (B007).
//!
//! Tests the full pipeline:
//! CanonicalAction -> Cedar PEP -> CredentialBroker -> Native GitHub Connector -> Wiremock -> Signed ActionReceipt -> Independent Verifier
//!
//! Enforces:
//! - Complete mediation and ActionHash binding
//! - Ephemeral credential lease consumption post-dispatch
//! - Ed25519 DSSE signed ActionReceipt production on Allow
//! - In-toto Statement v1.0 schema compliance
//! - AmbiguousMutation outcome detection and signed receipt generation on timeout
//! - Fail closed on Deny with ZERO receipt production

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{CredentialProviderType, Digest, InTotoStatement, PolicyEngine, PrincipalId};
use relay_policy::CedarPolicyEngine;
use relay_receipts::{base64_decode, Ed25519ReceiptSigner, ReceiptVerifier};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_SECRET_TOKEN: &str = "ghp_governed_pipeline_receipt_token_789";

async fn setup_pipeline(
    mock_server_uri: &str,
    request_timeout: Duration,
) -> (
    ActionCanonicalizer,
    Arc<CedarPolicyEngine>,
    Arc<JitCredentialBroker>,
    GitHubConnector,
    Ed25519ReceiptSigner,
) {
    let canonicalizer = ActionCanonicalizer::default();
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());

    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("github_token", TEST_SECRET_TOKEN.as_bytes().to_vec())
        .await;
    broker.register_provider(provider).await;

    let mut config = GitHubClientConfig::loopback_test(mock_server_uri);
    config.request_timeout = request_timeout;
    let client = Arc::new(GitHubClient::new(config).unwrap());
    let connector = GitHubConnector::new(client, "github_token");

    let signer = Ed25519ReceiptSigner::generate("relay-test-gateway-v1");

    (canonicalizer, policy_engine, broker, connector, signer)
}

#[tokio::test]
async fn test_full_pipeline_allow_produces_signed_verified_receipt() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .and(header(
            "authorization",
            format!("Bearer {TEST_SECRET_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 101,
            "number": 1,
            "title": "New issue",
            "state": "open"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let (canonicalizer, policy_engine, broker, connector, signer) =
        setup_pipeline(&mock_server.uri(), Duration::from_secs(5)).await;

    // 1. CanonicalAction
    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-engineer").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "create_issue");
    let args = serde_json::json!({
        "repo": "octocat/Hello-World",
        "title": "New issue",
        "body": "Detailed report"
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

    // 2. Cedar policy evaluation
    let auth_req = canonical_action.to_authorization_request().unwrap();
    let decision = policy_engine.evaluate(&auth_req).await.unwrap();
    assert!(decision.is_allowed());

    // 3. Execute governed with receipt
    let (result, receipt) = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &*broker, &signer)
        .await
        .expect("Execution with receipt must succeed");

    assert_eq!(result.exit_code, 0);
    assert!(!result.is_error);

    // 4. Verify receipt with public key
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    let verification = verifier.verify_receipt(
        &receipt,
        Some(&canonical_action.action_hash),
        Some(&decision.policy_digest),
    );
    assert!(
        verification.is_valid(),
        "Receipt verification failed: {:?}",
        verification
    );

    // 5. Verify DSSE envelope and in-toto schema
    assert_eq!(receipt.action_hash, canonical_action.action_hash);
    let payload_bytes = base64_decode(&receipt.dsse_envelope.payload).unwrap();
    assert_eq!(receipt.receipt_hash, Digest::compute(&payload_bytes));

    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(
        statement.subject[0].name,
        canonical_action.resource.as_str()
    );
    assert_eq!(
        statement.subject[0].digest.get("sha256").unwrap(),
        &canonical_action.action_hash.to_hex()
    );

    // 6. Verify zero secret leakage
    let statement_json = String::from_utf8(payload_bytes).unwrap();
    assert!(!statement_json.contains(TEST_SECRET_TOKEN));
}

#[tokio::test]
async fn test_ambiguous_mutation_timeout_produces_signed_receipt() {
    let mock_server = MockServer::start().await;

    // Simulate network delay causing timeout on mutating request
    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_delay(Duration::from_millis(500))
                .set_body_json(serde_json::json!({"id": 102})),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // Set request timeout to 100ms
    let (canonicalizer, policy_engine, broker, connector, signer) =
        setup_pipeline(&mock_server.uri(), Duration::from_millis(100)).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-engineer").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "create_issue");
    let args = serde_json::json!({
        "repo": "octocat/Hello-World",
        "title": "Timeout issue",
        "body": "This request will time out"
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

    // Must return Err with Some(receipt)
    let err_res = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &*broker, &signer)
        .await;

    assert!(err_res.is_err());
    let (exec_err, opt_receipt) = err_res.unwrap_err();
    assert!(exec_err.to_string().contains("Ambiguous mutation"));

    let receipt = opt_receipt.expect("Ambiguous mutation must produce an ActionReceipt");

    // Verify receipt status and observation
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    let verification = verifier.verify_receipt(&receipt, Some(&canonical_action.action_hash), None);
    assert!(verification.is_valid());

    let payload_bytes = base64_decode(&receipt.dsse_envelope.payload).unwrap();
    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes).unwrap();
    let obs = statement.predicate.observation;

    assert_eq!(obs.get("status").unwrap(), "AMBIGUOUS_MUTATION");
    assert_eq!(obs.get("is_ambiguous_mutation").unwrap(), true);
    assert_eq!(
        obs.get("retry_classification").unwrap(),
        "AmbiguousRequiresVerification"
    );
}

#[tokio::test]
async fn test_pipeline_deny_produces_no_receipt() {
    let mock_server = MockServer::start().await;

    // Zero requests expected on mock server
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let (canonicalizer, _policy_engine, broker, connector, signer) =
        setup_pipeline(&mock_server.uri(), Duration::from_secs(5)).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-engineer").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "create_issue");
    let args = serde_json::json!({
        "repo": "octocat/Hello-World",
        "title": "Denied issue",
        "body": "Should not execute"
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

    // Construct explicit Deny decision
    let deny_decision = relay_domain::PolicyDecision::deny(
        canonical_action.action_hash,
        Digest::compute(b"forbid;"),
        "Denied by test policy",
        vec!["forbid-all".to_string()],
    );

    let err_res = connector
        .execute_governed_with_receipt(&canonical_action, &deny_decision, None, &*broker, &signer)
        .await;

    assert!(err_res.is_err());
    let (exec_err, opt_receipt) = err_res.unwrap_err();
    assert!(
        opt_receipt.is_none(),
        "Denied action MUST NOT produce an ActionReceipt"
    );
    assert!(
        exec_err.to_string().contains("without prior authorization")
            || exec_err.to_string().contains("Unauthorized")
    );
}
