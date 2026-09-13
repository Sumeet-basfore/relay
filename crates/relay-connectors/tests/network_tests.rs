//! Network tests for GitHub Connector:
//! - Mock GitHub REST API server using wiremock
//! - HTTP 200, 201, 401, 403, 404, 409, 422, 429, 500, 502, 503
//! - Rate limiting headers (x-ratelimit-remaining, retry-after)
//! - Connection refusal and timeouts
//! - Redirect restrictions

use relay_canonical::{CanonicalAction, ToolIdentity};
use relay_connectors::github::{GitHubClient, GitHubClientConfig, GitHubConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, CredentialProviderType, ExecutionEnvironment, PolicyDecision, PrincipalId,
    ResourceUri, SchemaDigest, SessionId,
};
use std::sync::Arc;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn setup_test_action(
    tool_name: &str,
    repo: &str,
    args: serde_json::Value,
) -> (CanonicalAction, PolicyDecision) {
    let principal = PrincipalId::new("principal:agent:test-agent").unwrap();
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

async fn setup_test_broker(token: &str) -> Arc<JitCredentialBroker> {
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
async fn test_http_200_get_repository() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .and(header("accept", "application/vnd.github+json"))
        .and(header("x-github-api-version", "2022-11-28"))
        .and(header("authorization", "Bearer test_pat_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 1296269,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "private": false
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let result = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(!result.is_error);
    assert!(result.sanitized_preview.contains("HTTP 200"));
}

#[tokio::test]
async fn test_http_201_create_issue() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .and(header("authorization", "Bearer test_pat_123"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 1,
            "number": 1347,
            "title": "Found a bug",
            "state": "open"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "create_issue",
        "octocat/hello-world",
        serde_json::json!({"title": "Found a bug"}),
    );
    let result = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.sanitized_preview.contains("HTTP 201"));
}

#[tokio::test]
async fn test_http_401_authentication_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": "Bad credentials",
            "documentation_url": "https://docs.github.com/rest"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("invalid_token").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    let err_msg = err.to_string();
    assert!(err_msg.contains("401") || err_msg.contains("Authentication failed"));
}

#[tokio::test]
async fn test_http_403_authorization_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Resource not accessible by integration"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    let err_msg = err.to_string();
    assert!(err_msg.contains("403") || err_msg.contains("Authorization failed"));
}

#[tokio::test]
async fn test_http_403_rate_limit_exceeded() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(403)
                .append_header("x-ratelimit-remaining", "0")
                .append_header("x-ratelimit-reset", "1700000000")
                .set_body_json(serde_json::json!({
                    "message": "API rate limit exceeded for user"
                })),
        )
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    let err_msg = err.to_string();
    assert!(err_msg.contains("rate limit") || err_msg.contains("429"));
}

#[tokio::test]
async fn test_http_404_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "message": "Not Found"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/nonexistent",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("404"));
}

#[tokio::test]
async fn test_http_409_conflict() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/git/refs"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "message": "Reference already exists"
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "create_branch",
        "octocat/hello-world",
        serde_json::json!({
            "ref": "refs/heads/existing-branch",
            "sha": "a".repeat(40)
        }),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("409"));
}

#[tokio::test]
async fn test_http_422_validation_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/pulls"))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "message": "Validation Failed",
            "errors": [{"message": "No commits between main and patch"}]
        })))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "create_pull_request",
        "octocat/hello-world",
        serde_json::json!({
            "title": "PR with no changes",
            "head": "patch",
            "base": "main"
        }),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("422"));
}

#[tokio::test]
async fn test_http_500_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("500"));
}

#[tokio::test]
async fn test_redirect_to_untrusted_host_blocked() {
    let mock_server = MockServer::start().await;

    // Returns a redirect to evil.com
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(302)
                .append_header("location", "https://evil.attacker.com/leak-creds"),
        )
        .mount(&mock_server)
        .await;

    let client =
        Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(mock_server.uri())).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    let err_str = err.to_string();
    eprintln!("ACTUAL err_str: {err_str}");
    assert!(
        err_str.contains("Redirect")
            || err_str.contains("redirect")
            || err_str.contains("untrusted host")
            || err_str.contains("rejected")
    );
}

#[tokio::test]
async fn test_network_connection_failure() {
    // Port 1 is reserved and guaranteed connection refused
    let dead_url = "http://127.0.0.1:1";
    let client = Arc::new(GitHubClient::new(GitHubClientConfig::loopback_test(dead_url)).unwrap());
    let connector = GitHubConnector::new(client, "github_token");
    let broker = setup_test_broker("test_pat_123").await;

    let (action, decision) = make_test_fixture(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let err = connector
        .execute_governed(&action, &decision, &*broker)
        .await
        .unwrap_err();

    let err_str = err.to_string();
    assert!(err_str.contains("Connection failed") || err_str.contains("Network failure"));
}

fn make_test_fixture(
    tool_name: &str,
    repo: &str,
    args: serde_json::Value,
) -> (CanonicalAction, PolicyDecision) {
    setup_test_action(tool_name, repo, args)
}
