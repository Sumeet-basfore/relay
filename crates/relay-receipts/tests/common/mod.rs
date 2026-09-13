#![allow(dead_code)]

use chrono::Utc;
use relay_canonical::{CanonicalAction, ToolIdentity};
use relay_domain::{
    ActionHash, ActionId, Approval, ApprovalState, CredentialLease, CredentialProviderType,
    DecisionId, Digest, ExecutionEnvironment, PolicyDecision, PrincipalId, ResourceUri,
    SchemaDigest, SessionId,
};
use relay_receipts::Ed25519ReceiptSigner;

pub fn create_test_action() -> (CanonicalAction, ActionHash) {
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-runner").unwrap();
    let tool = ToolIdentity::parse("github.create_issue").unwrap();
    let resource = ResourceUri::parse("github://github.com/octocat/Hello-World").unwrap();
    let args = serde_json::json!({
        "owner": "octocat",
        "repo": "Hello-World",
        "title": "Security vulnerability report",
        "body": "Found a potential vulnerability in test environment"
    });
    let schema_digest = SchemaDigest::compute(b"{}");
    let env = ExecutionEnvironment::current();

    let mut action = CanonicalAction {
        action_id: ActionId::new_v7(),
        session_id,
        principal,
        mcp_method: "tools/call".to_string(),
        tool,
        resource,
        canonical_arguments: args,
        schema_digest,
        environment: env,
        action_hash: ActionHash::compute(b"placeholder"),
        canonical_bytes: Vec::new(),
        created_at: Utc::now(),
    };

    let computed_hash = ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
    action.action_hash = computed_hash;
    (action, computed_hash)
}

pub fn create_test_decision(action_hash: ActionHash, allow: bool) -> PolicyDecision {
    if allow {
        PolicyDecision::allow(
            action_hash,
            Digest::compute(b"permit(principal, action, resource);"),
            vec!["policy-allow-01".to_string()],
        )
    } else {
        PolicyDecision::deny(
            action_hash,
            Digest::compute(b"forbid(principal, action, resource);"),
            "Explicit forbid policy matched",
            vec!["policy-deny-01".to_string()],
        )
    }
}

pub fn create_test_approval(action_hash: ActionHash, state: ApprovalState) -> Approval {
    let mut approval = Approval::new(
        action_hash,
        DecisionId::new_v7(),
        "Approve issue creation in octocat/Hello-World",
        Some("device-001".to_string()),
        300,
    );
    match state {
        ApprovalState::Approved => {
            let approver = PrincipalId::new("principal:human:security-lead").unwrap();
            let _ = approval.approve(approver);
        }
        ApprovalState::Denied => {
            let approver = PrincipalId::new("principal:human:security-lead").unwrap();
            let _ = approval.deny(Some(approver));
        }
        _ => {}
    }
    approval
}

pub fn create_test_lease(
    action_hash: ActionHash,
    principal: &PrincipalId,
    resource: &ResourceUri,
) -> CredentialLease {
    CredentialLease::new(
        action_hash,
        principal.clone(),
        CredentialProviderType::KeyringStatic,
        "github_keyring_token",
        "github",
        resource.as_str(),
        60,
    )
}

pub fn create_test_signer() -> Ed25519ReceiptSigner {
    Ed25519ReceiptSigner::generate("test-ed25519-signer-v1")
}
