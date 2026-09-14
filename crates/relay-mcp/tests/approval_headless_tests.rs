use relay_domain::{
    ActionHash, Approval, ApprovalError, ApprovalMechanism, ApprovalProvider, ApprovalState,
    DecisionId, Digest, ExitCode, PrincipalId,
};
use relay_mcp::approval::headless::HeadlessApprovalGate;
use serde_json::json;

#[tokio::test]
async fn test_headless_gate_fails_closed() {
    let gate = HeadlessApprovalGate::new();

    let action_hash = ActionHash::compute(b"action_headless_delete");
    let mut approval = Approval::new_with_context(
        action_hash,
        DecisionId::new_v7(),
        "Delete critical repository",
        None,
        30,
        "github.delete_repository",
        PrincipalId::new("principal:agent:autonomous-agent").unwrap(),
        "org/critical-repo",
        Digest::from_bytes([0xbb; 32]),
        ApprovalMechanism::HeadlessGate,
    )
    .with_parameters_preview(json!({"confirm": true}));

    let result = gate.request_approval(&mut approval).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ApprovalError::NonInteractiveMode => {
            assert_eq!(approval.state, ApprovalState::Denied);
            assert_eq!(approval.mechanism, Some(ApprovalMechanism::HeadlessGate));
            assert!(approval
                .denial_reason
                .as_ref()
                .unwrap()
                .contains("Headless mode"));
        }
        other => panic!("Expected NonInteractiveMode, got {:?}", other),
    }

    // Verify exit code contract
    assert_eq!(ExitCode::EXIT_APPROVAL_REQUIRED, 7);
}
