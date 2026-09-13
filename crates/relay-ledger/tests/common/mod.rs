#![allow(dead_code)]

use chrono::Utc;
use relay_canonical::{CanonicalAction, ToolIdentity};
pub use relay_domain::ReceiptSigner;
use relay_domain::{
    ActionHash, ActionId, ActionReceipt, Digest, ExecutionEnvironment, ExecutionId,
    ExecutionObservationStatus, ExecutionRoute, OutputHash, PolicyDecision, PrincipalId,
    ResourceUri, SchemaDigest, SessionId,
};
use relay_receipts::{ActionReceiptBuilder, Ed25519ReceiptSigner};

pub fn create_test_signer() -> Ed25519ReceiptSigner {
    Ed25519ReceiptSigner::generate("test-ledger-signer-v1")
}

pub fn create_test_action(tool_name: &str) -> (CanonicalAction, ActionHash) {
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:test-runner").unwrap();
    let tool = ToolIdentity::parse(&format!("github.{tool_name}")).unwrap();
    let resource = ResourceUri::parse("github://github.com/octocat/Hello-World").unwrap();
    let args = serde_json::json!({
        "owner": "octocat",
        "repo": "Hello-World",
        "action": tool_name
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

pub fn create_test_decision(action_hash: ActionHash) -> PolicyDecision {
    PolicyDecision::allow(
        action_hash,
        Digest::compute(b"permit(principal, action, resource);"),
        vec!["policy-allow-01".to_string()],
    )
}

pub fn build_signed_test_receipt(
    signer: &Ed25519ReceiptSigner,
    tool_name: &str,
    parent_hash: Digest,
) -> ActionReceipt {
    let (action, action_hash) = create_test_action(tool_name);
    let decision = create_test_decision(action_hash);

    let execution_id = ExecutionId::new_v7();
    let started_at = Utc::now();
    let completed_at = started_at + chrono::Duration::milliseconds(25);

    let builder = ActionReceiptBuilder::new(&action, &decision)
        .with_parent_receipt_hash(parent_hash)
        .with_execution_metadata(
            execution_id,
            ExecutionRoute::Native,
            "github",
            tool_name,
            action.resource.as_str(),
            Some("POST".to_string()),
            Some(format!(
                "https://api.github.com/repos/octocat/Hello-World/{tool_name}"
            )),
            started_at,
            Some(completed_at),
            Some(25),
        )
        .with_observation(
            ExecutionObservationStatus::Success,
            0,
            OutputHash::compute(b"{\"ok\": true}"),
            None,
            12,
            Some(200),
            format!("Executed {tool_name} successfully"),
            false,
            "IdempotentSafeToRetry",
            None,
        );

    builder
        .build_and_sign(signer)
        .expect("Failed to build and sign test receipt")
}
