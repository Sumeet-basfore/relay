use chrono::{Duration, Utc};
use relay_domain::{
    ActionHash, Approval, ApprovalMechanism, ApprovalState, DecisionId, Digest, PrincipalId,
};
use relay_mcp::approval::prompt::{redact_sensitive_value, render_approval_prompt};
use serde_json::json;

fn dummy_approval() -> Approval {
    let action_hash = ActionHash::compute(b"action_42");
    let decision_id = DecisionId::new_v7();
    Approval::new_with_context(
        action_hash,
        decision_id,
        "Create PR on owner/repo",
        None,
        60,
        "github.create_pull_request",
        PrincipalId::new("principal:agent:test-agent").unwrap(),
        "owner/repo",
        Digest::from_bytes([0x01; 32]),
        ApprovalMechanism::TtyInteractive,
    )
    .with_parameters_preview(json!({
        "title": "Fix bug",
        "auth_token": "ghp_secrettoken1234567890",
        "nested": {
            "password": "secret_password",
            "normal": "hello"
        }
    }))
}

#[test]
fn test_approval_lifecycle_approve() {
    let mut approval = dummy_approval();
    assert_eq!(approval.state, ApprovalState::Pending);
    assert!(!approval.is_expired());

    approval
        .approve(PrincipalId::new("principal:user:human_operator").unwrap())
        .expect("approve");
    assert_eq!(approval.state, ApprovalState::Approved);
    assert_eq!(
        approval.approver,
        Some(PrincipalId::new("principal:user:human_operator").unwrap())
    );
    assert!(approval.resolved_at.is_some());
    assert_eq!(approval.denial_reason, None);
}

#[test]
fn test_approval_lifecycle_deny() {
    let mut approval = dummy_approval();
    approval
        .deny(
            Some(PrincipalId::new("principal:user:human_operator").unwrap()),
            Some("User rejected request".into()),
        )
        .expect("deny");
    assert_eq!(approval.state, ApprovalState::Denied);
    assert_eq!(
        approval.approver,
        Some(PrincipalId::new("principal:user:human_operator").unwrap())
    );
    assert_eq!(approval.denial_reason, Some("User rejected request".into()));
}

#[test]
fn test_approval_lifecycle_expire() {
    let mut approval = dummy_approval();
    approval.expire().expect("expire");
    assert_eq!(approval.state, ApprovalState::Expired);
}

#[test]
fn test_approval_lifecycle_cancel() {
    let mut approval = dummy_approval();
    approval.cancel().expect("cancel");
    assert_eq!(approval.state, ApprovalState::Cancelled);
}

#[test]
fn test_terminal_states_cannot_transition() {
    let mut approval = dummy_approval();
    approval
        .approve(PrincipalId::new("principal:user:human").unwrap())
        .unwrap();

    // Cannot deny an already approved approval
    assert!(approval.deny(None, None).is_err());
    // Cannot cancel an already approved approval
    assert!(approval.cancel().is_err());
    // Cannot expire an already approved approval
    assert!(approval.expire().is_err());
    // Cannot approve again
    assert!(approval
        .approve(PrincipalId::new("principal:user:another").unwrap())
        .is_err());

    let mut denied_approval = dummy_approval();
    denied_approval.deny(None, None).unwrap();
    // Cannot approve an already denied approval
    assert!(denied_approval
        .approve(PrincipalId::new("principal:user:human").unwrap())
        .is_err());
    assert!(denied_approval.cancel().is_err());
}

#[test]
fn test_action_hash_binding_validation() {
    let mut approval = dummy_approval();
    let action_hash = approval.action_hash;
    let agent_id = PrincipalId::new("principal:agent:test-agent").unwrap();
    let now = Utc::now();

    // Pending fails binding validation
    assert!(approval
        .validate_binding(
            &action_hash,
            Some(&agent_id),
            Some("owner/repo"),
            Some("github.create_pull_request"),
            now,
        )
        .is_err());

    approval
        .approve(PrincipalId::new("principal:user:human").unwrap())
        .unwrap();

    // Matching action_hash and context passes
    assert!(approval
        .validate_binding(
            &action_hash,
            Some(&agent_id),
            Some("owner/repo"),
            Some("github.create_pull_request"),
            now,
        )
        .is_ok());

    // Mismatched action_hash fails
    let wrong_hash = ActionHash::compute(b"wrong_action");
    assert!(approval
        .validate_binding(
            &wrong_hash,
            Some(&agent_id),
            Some("owner/repo"),
            Some("github.create_pull_request"),
            now,
        )
        .is_err());

    // Mismatched resource fails
    assert!(approval
        .validate_binding(
            &action_hash,
            Some(&agent_id),
            Some("different/repo"),
            Some("github.create_pull_request"),
            now,
        )
        .is_err());
}

#[test]
fn test_approval_expiration_logic() {
    let mut approval = dummy_approval();
    assert!(!approval.is_expired());

    // Backdate expires_at
    approval.expires_at = Utc::now() - Duration::seconds(10);
    assert!(approval.is_expired());

    // Approving an already expired approval fails
    assert!(approval
        .approve(PrincipalId::new("principal:user:human").unwrap())
        .is_err());
}

#[test]
fn test_vaulted_credential_redaction() {
    let raw = json!({
        "auth_token": "ghp_secret1234567890",
        "api_key": "my_secret_token",
        "nested": {
            "password": "super_secret_db_pass",
            "normal_field": "public_data"
        },
        "list": ["item_token", "normal_item"]
    });

    let redacted = redact_sensitive_value(&raw);

    assert_eq!(redacted["auth_token"], "[VAULTED]");
    assert_eq!(redacted["api_key"], "[VAULTED]");
    assert_eq!(redacted["nested"]["password"], "[VAULTED]");
    assert_eq!(redacted["nested"]["normal_field"], "public_data");

    // Ensure raw secret is never present in rendered prompt
    let approval = dummy_approval();
    let prompt_text = render_approval_prompt(&approval);
    assert!(!prompt_text.contains("ghp_secrettoken1234567890"));
    assert!(!prompt_text.contains("secret_password"));
    assert!(prompt_text.contains("[VAULTED]"));
    assert!(prompt_text.contains("github.create_pull_request"));
    assert!(prompt_text.contains("owner/repo"));
}
