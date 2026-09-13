//! End-to-end integration between B004 (Cedar PEP) and B005 (Credential Broker).
//!
//! Enforces:
//! - Canonical Action -> Cedar ALLOW -> CredentialBroker -> Ephemeral CredentialLease granted
//! - Canonical Action -> Cedar DENY -> CredentialBroker -> Fail-closed, AccessDenied, zero secrets leased
//! - Canonical Action -> Cedar APPROVAL_REQUIRED -> CredentialBroker -> Rejects acquisition prior to approval

use chrono::Utc;
use serde_json::json;
use std::sync::Arc;

use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::authorization::{AuthorizationRequest, PolicyDecisionType};
use relay_domain::credential::{CredentialProviderType, CredentialRequest};
use relay_domain::error::CredentialError;
use relay_domain::id::{PrincipalId, SessionId, ToolId};
use relay_domain::resource::ResourceUri;
use relay_domain::traits::{CredentialBroker, PolicyEngine};
use relay_policy::CedarPolicyEngine;

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

async fn setup_system() -> (CedarPolicyEngine, JitCredentialBroker) {
    let policy_engine = CedarPolicyEngine::default_engine().expect("Cedar policy engine");
    let broker = JitCredentialBroker::new();

    // Register test providers
    let github_provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::GithubApp,
    ));
    github_provider
        .add_secret("github-default", b"ghs_ephemeral_app_token_999".to_vec())
        .await;
    broker.register_provider(github_provider).await;

    let keyring_provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    keyring_provider
        .add_secret("fs-key", b"internal_fs_key".to_vec())
        .await;
    keyring_provider
        .add_secret("postgres-key", b"pg_read_user_token".to_vec())
        .await;
    broker.register_provider(keyring_provider).await;

    (policy_engine, broker)
}

#[tokio::test]
async fn test_integration_cedar_allow_grants_credential_lease() {
    let (policy_engine, broker) = setup_system().await;

    // 1. Authorized GitHub read action
    let auth_req = make_auth_request(
        "principal:agent:default",
        "github.read",
        "github://github.com/relay-security/relay",
        "github",
        "read",
        json!({ "repo": "relay-security/relay" }),
        "/workspace",
    );

    // 2. Cedar PEP evaluation -> ALLOW
    let decision = policy_engine.evaluate(&auth_req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Allow);
    assert!(decision.is_allowed());

    // 3. JIT Credential Request using authorizing decision
    let cred_req = CredentialRequest::new(
        decision.action_hash,
        auth_req.principal.clone(),
        auth_req.resource.clone(),
        CredentialProviderType::GithubApp,
        "github-default",
        "https://api.github.com",
        "repo:relay-security/relay:read",
        60,
    );

    let (lease, secret) = broker
        .acquire_lease(&cred_req, &decision)
        .await
        .expect("Credential acquisition must succeed on ALLOW");

    assert_eq!(lease.action_hash, decision.action_hash);
    assert_eq!(lease.principal, auth_req.principal);
    assert_eq!(secret.as_bytes(), b"ghs_ephemeral_app_token_999");
    assert!(!lease.is_expired());
    assert!(broker.validate_lease(&lease).await.unwrap());
}

#[tokio::test]
async fn test_integration_cedar_deny_blocks_credential_acquisition() {
    let (policy_engine, broker) = setup_system().await;

    // 1. Forbidden action: reading .env secret file
    let auth_req = make_auth_request(
        "principal:agent:default",
        "fs.read",
        "file:///workspace/.env",
        "fs",
        "read",
        json!({ "path": "/workspace/.env" }),
        "/workspace",
    );

    // 2. Cedar PEP evaluation -> DENY
    let decision = policy_engine.evaluate(&auth_req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Deny);
    assert!(!decision.is_allowed());

    // 3. Attempt to acquire credential with DENY decision
    let cred_req = CredentialRequest::new(
        decision.action_hash,
        auth_req.principal.clone(),
        auth_req.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "fs-key",
        "file:///workspace",
        "file:read",
        60,
    );

    let err = broker
        .acquire_lease(&cred_req, &decision)
        .await
        .expect_err("Broker MUST reject credential acquisition on DENY");

    match err {
        CredentialError::AccessDenied { reason } => {
            assert!(
                reason.contains("forbid") || reason.contains("Denied"),
                "Expected policy rejection reason, got {reason}"
            );
        }
        other => panic!("Expected AccessDenied, got {other:?}"),
    }

    assert_eq!(broker.active_lease_count().await, 0);
}

#[tokio::test]
async fn test_integration_cedar_approval_required_blocks_credential_prematurely() {
    let (policy_engine, broker) = setup_system().await;

    // 1. Destructive action requiring step-up operator approval: fs.delete
    let auth_req = make_auth_request(
        "principal:agent:default",
        "fs.delete",
        "file:///workspace/temp_output.log",
        "fs",
        "delete",
        json!({ "path": "/workspace/temp_output.log" }),
        "/workspace",
    );

    // 2. Cedar PEP evaluation -> APPROVAL_REQUIRED
    let decision = policy_engine.evaluate(&auth_req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::ApprovalRequired);
    assert!(decision.requires_approval());

    // 3. Attempt to acquire credential prior to human approval
    let cred_req = CredentialRequest::new(
        decision.action_hash,
        auth_req.principal.clone(),
        auth_req.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "fs-key",
        "file:///workspace",
        "file:delete",
        60,
    );

    let err = broker
        .acquire_lease(&cred_req, &decision)
        .await
        .expect_err("Broker MUST reject credential acquisition when APPROVAL_REQUIRED");

    match err {
        CredentialError::ApprovalRequired { action_hash } => {
            assert_eq!(action_hash, decision.action_hash.to_hex());
        }
        other => panic!("Expected ApprovalRequired, got {other:?}"),
    }

    assert_eq!(broker.active_lease_count().await, 0);
}

#[tokio::test]
async fn test_integration_default_deny_unknown_tool_blocks_credentials() {
    let (policy_engine, broker) = setup_system().await;

    // 1. Unknown / unregistered action
    let auth_req = make_auth_request(
        "principal:agent:default",
        "unregistered_tool.exec",
        "tool://custom/exec",
        "custom",
        "exec",
        json!({ "arg": "val" }),
        "/workspace",
    );

    // 2. Cedar PEP evaluation -> Default Deny
    let decision = policy_engine.evaluate(&auth_req).await.expect("evaluate");
    assert_eq!(decision.decision, PolicyDecisionType::Deny);

    let cred_req = CredentialRequest::new(
        decision.action_hash,
        auth_req.principal.clone(),
        auth_req.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "fs-key",
        "tool://custom",
        "exec",
        60,
    );

    let err = broker
        .acquire_lease(&cred_req, &decision)
        .await
        .unwrap_err();
    assert!(matches!(err, CredentialError::AccessDenied { .. }));
}
