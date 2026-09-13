//! Performance Characterization Tests for B006 Native GitHub Connector.
//!
//! Measures:
//! 1. Local operation parsing and validation duration
//! 2. JIT credential lease acquisition and validation duration
//! 3. Total end-to-end execution pipeline latency (separating local overhead from network)
//! 4. Verifies local pipeline overhead is well under architectural targets (< 5 ms)

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::github::{
    GitHubClient, GitHubClientConfig, GitHubConnector, GitHubOperation,
};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{CredentialProviderType, PolicyEngine, PrincipalId};
use relay_policy::CedarPolicyEngine;
use std::sync::Arc;
use std::time::Instant;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BENCH_TOKEN: &str = "ghp_benchmark_token_secret_123456789";

#[tokio::test]
async fn test_performance_characterization() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "id": 1296269,
        "name": "hello-world",
        "full_name": "octocat/hello-world",
        "private": false,
        "owner": {
            "login": "octocat",
            "id": 1
        }
    });

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .and(header("authorization", format!("Bearer {BENCH_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    // Pipeline components
    let canonicalizer = ActionCanonicalizer::default();
    let policy_engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("github_token", BENCH_TOKEN.as_bytes().to_vec())
        .await;
    broker.register_provider(provider).await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "github", "get_repository");
    let args = serde_json::json!({"repo": "octocat/hello-world"});

    // 1. Benchmark Canonicalization
    let iterations = 500;
    let start_canon = Instant::now();
    let mut canonical_action = canonicalizer
        .canonicalize(
            session_id,
            principal.clone(),
            "tools/call",
            tool_ident.clone(),
            &args,
            None,
            None,
        )
        .unwrap();
    for _ in 0..iterations {
        canonical_action = canonicalizer
            .canonicalize(
                session_id,
                principal.clone(),
                "tools/call",
                tool_ident.clone(),
                &args,
                None,
                None,
            )
            .unwrap();
    }
    let avg_canon = start_canon.elapsed() / iterations;

    // 2. Benchmark Cedar Policy Evaluation
    let auth_req = canonical_action.to_authorization_request().unwrap();
    let start_policy = Instant::now();
    let mut decision = policy_engine.evaluate(&auth_req).await.unwrap();
    for _ in 0..iterations {
        decision = policy_engine.evaluate(&auth_req).await.unwrap();
    }
    let avg_policy = start_policy.elapsed() / iterations;

    // 3. Benchmark Local Operation Parsing
    let start_op = Instant::now();
    for _ in 0..iterations {
        let op = GitHubOperation::from_canonical_action(&canonical_action).unwrap();
        let _ = op.http_method();
        let _ = op.endpoint_path("octocat", "hello-world");
        let _ = op.serialize_body().unwrap();
    }
    let avg_op = start_op.elapsed() / iterations;

    // 4. Benchmark Full Execution (Local + Mock Loopback Network)
    let e2e_iterations = 100;
    let start_e2e = Instant::now();
    for _ in 0..e2e_iterations {
        let result = connector
            .execute_governed(&canonical_action, &decision, &*broker)
            .await
            .unwrap();
        assert_eq!(result.exit_code, 0);
    }
    let avg_e2e = start_e2e.elapsed() / e2e_iterations;

    println!("\n=== B006 GitHub Connector Performance Profile ===");
    println!("Action Canonicalization: {:?}", avg_canon);
    println!("Cedar Policy Evaluation: {:?}", avg_policy);
    println!("Local Operation Parsing: {:?}", avg_op);
    println!(
        "Full Governed Roundtrip (Local + Mock Network): {:?}",
        avg_e2e
    );

    // Verify local operational overhead is minimal
    assert!(
        avg_op.as_micros() < 500,
        "Local operation parsing must be under 500 µs (was {:?})",
        avg_op
    );
    assert!(
        avg_canon.as_millis() < 5,
        "Canonicalization must be under 5 ms (was {:?})",
        avg_canon
    );
    assert!(
        avg_policy.as_millis() < 5,
        "Cedar policy check must be under 5 ms (was {:?})",
        avg_policy
    );
    assert!(
        avg_e2e.as_millis() < 50,
        "Full roundtrip with mock network must be under 50 ms (was {:?})",
        avg_e2e
    );
}
