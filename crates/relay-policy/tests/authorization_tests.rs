//! Exhaustive Cedar authorization tests for Relay MVP.
//!
//! Validates:
//! - Safe permitted operations (filesystem, github, postgres)
//! - Explicit forbid overrides (sensitive credential files, destructive DDL)
//! - Step-up human approval annotations (@approval_required, @advice)
//! - Strict default-deny for unmentioned actions
//! - Cryptographic action_hash and policy_digest integrity (SI-010)

use chrono::Utc;
use relay_domain::{
    AuthorizationRequest, PolicyDecisionType, PolicyEngine, PrincipalId, ResourceUri, SessionId,
    ToolId,
};
use relay_policy::CedarPolicyEngine;
use serde_json::json;

fn make_auth_request(
    principal: &str,
    action: &str,
    resource: &str,
    tool_ns: &str,
    tool_name: &str,
    args: serde_json::Value,
    cwd: &str,
) -> AuthorizationRequest {
    AuthorizationRequest {
        principal: PrincipalId::new(principal).unwrap(),
        action: action.to_string(),
        resource: ResourceUri::parse(resource).unwrap(),
        session_id: SessionId::new_v7(),
        tool: ToolId::new(tool_ns, tool_name).unwrap(),
        arguments: args,
        working_directory: cwd.to_string(),
        timestamp: Utc::now(),
        action_hash: None,
    }
}

#[tokio::test]
async fn test_permit_safe_filesystem_read() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "fs.read",
        "file:///workspace/src/main.rs",
        "fs",
        "read",
        json!({ "path": "/workspace/src/main.rs" }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Allow);
    assert!(decision.is_allowed());
    assert!(!decision.is_denied());
    assert!(!decision.requires_approval());
    assert_eq!(decision.action_hash, req.compute_action_hash());
    assert_eq!(decision.policy_digest, engine.policy_digest());
    assert!(decision
        .determining_policies
        .contains(&"permit_fs_reads".to_string()));
}

#[tokio::test]
async fn test_permit_safe_github_read() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "github.read",
        "github://github.com/relay-security/relay",
        "github",
        "read",
        json!({ "repo": "relay-security/relay" }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Allow);
    assert!(decision.is_allowed());
    assert!(decision
        .determining_policies
        .contains(&"permit_github_reads".to_string()));
}

#[tokio::test]
async fn test_permit_safe_postgres_query() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "postgres.read",
        "postgres://localhost/mydb/public.metrics",
        "postgres",
        "read",
        json!({ "query": "SELECT count(*) FROM metrics;" }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Allow);
    assert!(decision.is_allowed());
    assert!(decision
        .determining_policies
        .contains(&"permit_postgres_reads".to_string()));
}

#[tokio::test]
async fn test_forbid_sensitive_env_file() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "fs.read",
        "file:///workspace/.env",
        "fs",
        "read",
        json!({ "path": "/workspace/.env" }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Deny);
    assert!(decision.is_denied());
    assert!(!decision.is_allowed());
    assert!(decision
        .determining_policies
        .contains(&"forbid_sensitive_files".to_string()));
    assert_eq!(
        decision.reason.as_deref(),
        Some("Action explicitly forbidden by policy")
    );
}

#[tokio::test]
async fn test_forbid_sensitive_ssh_keys() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let sensitive_paths = [
        "/home/user/.ssh/id_rsa",
        "/home/user/.ssh/id_ed25519",
        "/root/.aws/credentials",
        "/workspace/.env.production",
        "/workspace/.relay/keys/node.key",
    ];

    for path in sensitive_paths {
        let req = make_auth_request(
            "principal:agent:default",
            "fs.read",
            &format!("file://{path}"),
            "fs",
            "read",
            json!({ "path": path }),
            "/workspace",
        );

        let decision = engine.evaluate(&req).await.expect("evaluate");
        assert_eq!(
            decision.decision,
            PolicyDecisionType::Deny,
            "Path '{path}' must be forbidden"
        );
        assert!(decision
            .determining_policies
            .contains(&"forbid_sensitive_files".to_string()));
    }
}

#[tokio::test]
async fn test_forbid_destructive_postgres_ddl() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "postgres.ddl",
        "postgres://localhost/mydb/public.users",
        "postgres",
        "ddl",
        json!({
            "query": "DROP TABLE users;",
            "is_destructive": true
        }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Deny);
    assert!(decision.is_denied());
    assert!(decision
        .determining_policies
        .contains(&"forbid_postgres_ddl".to_string()));
}

#[tokio::test]
async fn test_step_up_human_approval_on_delete() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "fs.delete",
        "file:///workspace/temp_output.log",
        "fs",
        "delete",
        json!({ "path": "/workspace/temp_output.log" }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::ApprovalRequired);
    assert!(decision.requires_approval());
    assert!(!decision.is_allowed());
    assert!(!decision.is_denied());
    assert!(decision
        .determining_policies
        .contains(&"require_approval_fs_delete".to_string()));
    assert!(decision
        .reason
        .as_deref()
        .unwrap()
        .contains("operator approval required"));
}

#[tokio::test]
async fn test_strict_default_deny_unpermitted_action() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = make_auth_request(
        "principal:agent:default",
        "shell.execute",
        "tool://shell/execute",
        "shell",
        "execute",
        json!({ "command": "rm -rf /" }),
        "/workspace",
    );

    let decision = engine.evaluate(&req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Deny);
    assert!(decision.is_denied());
    // In strict default-deny, no policy matched, so determining policies is empty
    assert!(decision.determining_policies.is_empty());
    assert_eq!(
        decision.reason.as_deref(),
        Some("Action not permitted by policy (default deny)")
    );
}

#[tokio::test]
async fn test_strict_default_deny_unknown_principal() {
    // Test custom policy where only a specific agent is allowed
    let policy_src = r#"
    @id("permit_admin_only")
    permit (
        principal == Relay::Agent::"principal:agent:admin",
        action == Relay::Action::"fs.read",
        resource
    );
    "#;

    let engine = CedarPolicyEngine::from_str(policy_src, None).expect("engine");

    // Default agent should be denied
    let req_unauthorized = make_auth_request(
        "principal:agent:untrusted",
        "fs.read",
        "file:///workspace/data.txt",
        "fs",
        "read",
        json!({ "path": "/workspace/data.txt" }),
        "/workspace",
    );
    let decision_unauth = engine.evaluate(&req_unauthorized).await.expect("evaluate");
    assert_eq!(decision_unauth.decision, PolicyDecisionType::Deny);
    assert!(decision_unauth.determining_policies.is_empty());

    // Admin agent should be allowed
    let req_authorized = make_auth_request(
        "principal:agent:admin",
        "fs.read",
        "file:///workspace/data.txt",
        "fs",
        "read",
        json!({ "path": "/workspace/data.txt" }),
        "/workspace",
    );
    let decision_auth = engine.evaluate(&req_authorized).await.expect("evaluate");
    assert_eq!(decision_auth.decision, PolicyDecisionType::Allow);
    assert_eq!(
        decision_auth.determining_policies,
        vec!["permit_admin_only".to_string()]
    );
}
