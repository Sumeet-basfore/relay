use relay_canonical::{CanonicalAction, GitHubNormalizer, GitHubSubResource, ToolIdentity};
use relay_connectors::github::{GitHubConnector, GitHubError, GitHubOperation, IdempotencyClass};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, CredentialProviderType, ExecutionEnvironment, NativeConnector, PolicyDecision,
    PrincipalId, ResourceUri, SchemaDigest, SessionId,
};
use std::sync::Arc;

fn make_canonical_action(
    tool_name: &str,
    repo: &str,
    args: serde_json::Value,
) -> (CanonicalAction, ActionHash) {
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
    (action, computed_hash)
}

#[test]
fn test_resource_mapping_repository() {
    let norm = GitHubNormalizer::parse("https://github.com/octocat/Hello-World").unwrap();
    assert_eq!(norm.owner, "octocat");
    assert_eq!(norm.repo, "hello-world");
    assert_eq!(norm.sub_resource, None);
    assert_eq!(
        norm.canonical_uri.as_str(),
        "github://github.com/octocat/hello-world"
    );
}

#[test]
fn test_resource_mapping_pull_request() {
    let norm = GitHubNormalizer::parse("octocat/hello-world/pull/42").unwrap();
    assert_eq!(norm.owner, "octocat");
    assert_eq!(norm.repo, "hello-world");
    assert_eq!(norm.sub_resource, Some(GitHubSubResource::PullRequest(42)));
    assert_eq!(
        norm.canonical_uri.as_str(),
        "github://github.com/octocat/hello-world/pull/42"
    );
}

#[test]
fn test_resource_mapping_issue() {
    let norm = GitHubNormalizer::parse("octocat/hello-world#101").unwrap();
    assert_eq!(norm.owner, "octocat");
    assert_eq!(norm.repo, "hello-world");
    assert_eq!(norm.sub_resource, Some(GitHubSubResource::Issue(101)));
    assert_eq!(
        norm.canonical_uri.as_str(),
        "github://github.com/octocat/hello-world/issues/101"
    );
}

#[test]
fn test_resource_mapping_branch_ref() {
    let norm = GitHubNormalizer::parse("octocat/hello-world@feature-branch").unwrap();
    assert_eq!(norm.owner, "octocat");
    assert_eq!(norm.repo, "hello-world");
    assert_eq!(
        norm.sub_resource,
        Some(GitHubSubResource::Ref("feature-branch".to_string()))
    );
    assert_eq!(
        norm.canonical_uri.as_str(),
        "github://github.com/octocat/hello-world/refs/feature-branch"
    );
}

#[test]
fn test_resource_mapping_rejects_path_traversal() {
    assert!(GitHubNormalizer::parse("octocat/../malicious/repo").is_err());
    assert!(GitHubNormalizer::parse("octocat/hello-world/../../etc/passwd").is_err());
}

#[test]
fn test_resource_mapping_rejects_malformed_chars() {
    assert!(GitHubNormalizer::parse("octocat/repo;rm -rf").is_err());
    assert!(GitHubNormalizer::parse("octocat/repo with spaces").is_err());
}

#[test]
fn test_operation_mapping_get_repository() {
    let (action, _) = make_canonical_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let op = GitHubOperation::from_canonical_action(&action).unwrap();
    assert_eq!(op, GitHubOperation::GetRepository);
    assert_eq!(op.http_method(), reqwest::Method::GET);
    assert_eq!(
        op.endpoint_path("octocat", "hello-world"),
        "/repos/octocat/hello-world"
    );
    assert_eq!(op.idempotency_class(), IdempotencyClass::SafeToRetry);
    assert!(!op.is_mutating());
}

#[test]
fn test_operation_mapping_get_pull_request() {
    let (action, _) = make_canonical_action(
        "get_pull_request",
        "octocat/hello-world/pull/42",
        serde_json::json!({"pull_number": 42}),
    );
    let op = GitHubOperation::from_canonical_action(&action).unwrap();
    assert_eq!(op, GitHubOperation::GetPullRequest { pull_number: 42 });
    assert_eq!(op.http_method(), reqwest::Method::GET);
    assert_eq!(
        op.endpoint_path("octocat", "hello-world"),
        "/repos/octocat/hello-world/pulls/42"
    );
    assert_eq!(op.idempotency_class(), IdempotencyClass::SafeToRetry);
    assert!(!op.is_mutating());
}

#[test]
fn test_operation_mapping_get_issue() {
    let (action, _) = make_canonical_action(
        "get_issue",
        "octocat/hello-world/issues/99",
        serde_json::json!({"issue_number": 99}),
    );
    let op = GitHubOperation::from_canonical_action(&action).unwrap();
    assert_eq!(op, GitHubOperation::GetIssue { issue_number: 99 });
    assert_eq!(op.http_method(), reqwest::Method::GET);
    assert_eq!(
        op.endpoint_path("octocat", "hello-world"),
        "/repos/octocat/hello-world/issues/99"
    );
}

#[test]
fn test_operation_mapping_create_issue() {
    let (action, _) = make_canonical_action(
        "create_issue",
        "octocat/hello-world",
        serde_json::json!({
            "title": "Bug in authentication",
            "body": "Detailed report...",
            "labels": ["bug", "security"]
        }),
    );
    let op = GitHubOperation::from_canonical_action(&action).unwrap();
    assert!(op.is_mutating());
    assert_eq!(op.idempotency_class(), IdempotencyClass::NotSafeToRetry);
    assert_eq!(op.http_method(), reqwest::Method::POST);
    assert_eq!(
        op.endpoint_path("octocat", "hello-world"),
        "/repos/octocat/hello-world/issues"
    );
}

#[test]
fn test_operation_mapping_create_pull_request() {
    let (action, _) = make_canonical_action(
        "create_pull_request",
        "octocat/hello-world",
        serde_json::json!({
            "title": "Fix security vulnerability",
            "head": "patch-1",
            "base": "main",
            "body": "Fixes CVE-2026-1234"
        }),
    );
    let op = GitHubOperation::from_canonical_action(&action).unwrap();
    assert!(op.is_mutating());
    assert_eq!(
        op.idempotency_class(),
        IdempotencyClass::ConditionallyRetryable
    );
    assert_eq!(op.http_method(), reqwest::Method::POST);
    assert_eq!(
        op.endpoint_path("octocat", "hello-world"),
        "/repos/octocat/hello-world/pulls"
    );
}

#[test]
fn test_operation_mapping_create_branch() {
    let sha = "a".repeat(40);
    let (action, _) = make_canonical_action(
        "create_branch",
        "octocat/hello-world",
        serde_json::json!({
            "ref": "refs/heads/feature-gate",
            "sha": sha
        }),
    );
    let op = GitHubOperation::from_canonical_action(&action).unwrap();
    assert!(op.is_mutating());
    assert_eq!(
        op.idempotency_class(),
        IdempotencyClass::ConditionallyRetryable
    );
    assert_eq!(op.http_method(), reqwest::Method::POST);
    assert_eq!(
        op.endpoint_path("octocat", "hello-world"),
        "/repos/octocat/hello-world/git/refs"
    );
}

#[test]
fn test_operation_mapping_rejects_unsupported() {
    let (action, _) = make_canonical_action(
        "delete_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );
    let res = GitHubOperation::from_canonical_action(&action);
    assert!(matches!(res, Err(GitHubError::UnsupportedOperation(_))));
}

#[test]
fn test_operation_mapping_rejects_unknown_fields_in_write() {
    let (action, _) = make_canonical_action(
        "create_issue",
        "octocat/hello-world",
        serde_json::json!({
            "title": "Valid title",
            "malicious_extra_field": "passthrough_attempt"
        }),
    );
    let res = GitHubOperation::from_canonical_action(&action);
    assert!(matches!(res, Err(GitHubError::InvalidArguments { .. })));
}

#[test]
fn test_operation_pr_number_confusion_rejection() {
    // Canonical ResourceUri is PR #10, but arguments claim PR #20
    let (action, _) = make_canonical_action(
        "get_pull_request",
        "octocat/hello-world/pull/10",
        serde_json::json!({"pull_number": 20}),
    );
    let res = GitHubOperation::from_canonical_action(&action);
    assert!(matches!(res, Err(GitHubError::ResourceMismatch { .. })));
}

#[tokio::test]
async fn test_action_hash_mismatch_rejected_without_network() {
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("github_token", b"fake_pat".to_vec())
        .await;
    broker.register_provider(provider).await;

    let (action, _action_hash) = make_canonical_action(
        "get_repository",
        "octocat/hello-world",
        serde_json::json!({}),
    );

    // Decision has mismatched ActionHash
    let mismatched_hash = ActionHash::compute(b"different_action");
    let decision = PolicyDecision::allow(
        mismatched_hash,
        relay_domain::Digest::compute(b"schema"),
        vec!["permit_github_reads".to_string()],
    );

    let connector = GitHubConnector::default_production().unwrap();
    let result = connector
        .execute_governed(&action, &decision, &*broker)
        .await;

    assert!(result.is_err());
    let err_str = result.err().unwrap().to_string();
    assert!(err_str.contains("ActionHash mismatch") || err_str.contains("SI-005"));
}

#[tokio::test]
async fn test_connector_requires_secret_buffer_in_trait_execute() {
    let connector = GitHubConnector::default_production().unwrap();
    let res = connector
        .execute(
            "get_repository",
            &serde_json::json!({"repo": "octocat/hello-world"}),
            None,
        )
        .await;
    assert!(res.is_err());
    assert!(res.err().unwrap().to_string().contains("SecretBuffer"));
}
