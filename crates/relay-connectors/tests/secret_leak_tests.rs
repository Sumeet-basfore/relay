//! Secret-leak tests for GitHub Connector.
//!
//! Enforces Invariant SI-001 (Zero Target Credentials in Observable Outputs):
//! Proves that the secret token (RELAY_TEST_GITHUB_SECRET_DO_NOT_LEAK_123) NEVER appears in:
//! - Returned errors (Display and Debug formats)
//! - Captured structured log output
//! - URLs and query parameters sent to the network
//! - Agent-facing sanitized execution previews

use relay_canonical::{CanonicalAction, ToolIdentity};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, CredentialProviderType, ExecutionEnvironment, PolicyDecision, PrincipalId,
    ResourceUri, SchemaDigest, SessionId,
};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CANARY_SECRET: &str = "RELAY_TEST_GITHUB_SECRET_DO_NOT_LEAK_123";

#[derive(Clone)]
struct TestLogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl TestLogCapture {
    fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn contents(&self) -> String {
        let lock = self.buffer.lock().unwrap();
        String::from_utf8_lossy(&lock).to_string()
    }
}

impl MakeWriter<'_> for TestLogCapture {
    type Writer = TestLogWriter;

    fn make_writer(&self) -> Self::Writer {
        TestLogWriter {
            buffer: self.buffer.clone(),
        }
    }
}

struct TestLogWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for TestLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut lock = self.buffer.lock().unwrap();
        lock.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn create_test_action(tool_name: &str, repo: &str) -> (CanonicalAction, PolicyDecision) {
    let principal = PrincipalId::new("principal:agent:secret-leak-tester").unwrap();
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
        canonical_arguments: serde_json::json!({}),
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

#[tokio::test]
async fn test_secret_never_in_success_preview_or_url() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1,
            "name": "hello-world"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker(CANARY_SECRET).await;

    let (action, decision) = create_test_action("get_repository", "octocat/hello-world");
    let result = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap();

    // 1. Agent preview must not contain canary
    assert!(!result.sanitized_preview.contains(CANARY_SECRET));

    // 2. Wiremock recorded URL and path must not contain canary
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert!(!req.url.as_str().contains(CANARY_SECRET));
    assert!(!req.url.path().contains(CANARY_SECRET));
    assert_eq!(req.url.query(), None);
}

#[tokio::test]
async fn test_secret_never_in_error_display_or_debug() {
    let mock_server = MockServer::start().await;

    // Simulate 403 Forbidden with server error body
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Resource forbidden",
            "documentation_url": "https://docs.github.com"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker(CANARY_SECRET).await;

    let (action, decision) = create_test_action("get_repository", "octocat/hello-world");
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    // Verify Display representation
    let err_display = format!("{}", err);
    assert!(
        !err_display.contains(CANARY_SECRET),
        "Canary secret found in ExecutionError Display output!"
    );

    // Verify Debug representation
    let err_debug = format!("{:?}", err);
    assert!(
        !err_debug.contains(CANARY_SECRET),
        "Canary secret found in ExecutionError Debug output!"
    );
}

#[tokio::test]
async fn test_secret_never_in_captured_tracing_logs() {
    let log_capture = TestLogCapture::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log_capture.clone())
        .with_ansi(false)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = create_test_broker(CANARY_SECRET).await;

    let (action, decision) = create_test_action("get_repository", "octocat/hello-world");
    let _ = connector
        .execute_governed(&action, &decision, &*broker)
        .await;

    // Flush and inspect captured logs
    let logs = log_capture.contents();
    assert!(
        !logs.contains(CANARY_SECRET),
        "Canary secret leaked into tracing logs!"
    );
}
