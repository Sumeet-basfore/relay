use relay_domain::action::{Action, ActionState, RequestedAction};
use relay_domain::approval::{Approval, ApprovalState};
use relay_domain::credential::{CredentialLease, CredentialProviderType, LeaseState};
use relay_domain::execution::{Execution, ExecutionResult, ExecutionRoute, ExecutionState};
use relay_domain::id::*;
use relay_domain::resource::ResourceUri;
use relay_domain::session::{Session, SessionState};

#[test]
fn test_action_state_transitions() {
    let session_id = SessionId::new_v7();
    let tool_id = ToolId::new("fs", "read_file").unwrap();

    let req = RequestedAction {
        method: "tools/call".to_string(),
        tool_name: "read_file".to_string(),
        raw_arguments: serde_json::json!({"path": "test.txt"}),
    };

    let mut action = Action::new(session_id, tool_id, req);
    assert_eq!(action.state, ActionState::Proposed);

    // Transition: Proposed -> Authorized
    let action_hash = ActionHash::from_hex(&"2".repeat(64)).unwrap();
    let decision_id = DecisionId::new_v7();
    action
        .mark_authorized(action_hash, decision_id)
        .expect("Valid authorization");
    assert_eq!(action.state, ActionState::Authorized);

    // Transition: Authorized -> Executing
    let exec_id = ExecutionId::new_v7();
    action
        .mark_executing(exec_id)
        .expect("Valid execution transition");
    assert_eq!(action.state, ActionState::Executing);

    // Transition: Executing -> Executed
    action.mark_executed().expect("Valid executed transition");
    assert_eq!(action.state, ActionState::Executed);

    // Transition: Executed -> Settled
    action.settle().expect("Valid settle transition");
    assert_eq!(action.state, ActionState::Settled);

    // Terminal state cannot transition anywhere
    assert!(action.mark_approved().is_err());
    assert!(action.mark_rejected().is_err());
}

#[test]
fn test_action_approval_path() {
    let session_id = SessionId::new_v7();
    let tool_id = ToolId::new("fs", "write_file").unwrap();

    let req = RequestedAction {
        method: "tools/call".to_string(),
        tool_name: "write_file".to_string(),
        raw_arguments: serde_json::json!({}),
    };

    let mut action = Action::new(session_id, tool_id, req);
    let action_hash = ActionHash::from_hex(&"2".repeat(64)).unwrap();
    let decision_id = DecisionId::new_v7();
    let approval_id = ApprovalId::new_v7();

    // Policy requires approval
    action
        .mark_awaiting_approval(action_hash, decision_id, approval_id)
        .expect("Valid awaiting approval");
    assert_eq!(action.state, ActionState::AwaitingApproval);

    // Human approves
    action.mark_approved().expect("Valid approval");
    assert_eq!(action.state, ActionState::Approved);

    // Approved -> Executing
    let exec_id = ExecutionId::new_v7();
    action
        .mark_executing(exec_id)
        .expect("Valid executing transition");
    assert_eq!(action.state, ActionState::Executing);
}

#[test]
fn test_action_rejection_path() {
    let session_id = SessionId::new_v7();
    let tool_id = ToolId::new("fs", "delete_file").unwrap();

    let req = RequestedAction {
        method: "tools/call".to_string(),
        tool_name: "delete_file".to_string(),
        raw_arguments: serde_json::json!({}),
    };

    let mut action = Action::new(session_id, tool_id, req);
    action.mark_rejected().expect("Valid rejection");
    assert_eq!(action.state, ActionState::Rejected);

    action.settle().expect("Can settle rejected action");
    assert_eq!(action.state, ActionState::Settled);
}

#[test]
fn test_session_state_transitions() {
    let principal_id = PrincipalId::new("principal:user:local").unwrap();

    let mut session = Session::new(principal_id, "/workspace", None);
    assert_eq!(session.state, SessionState::Created);

    // Activate
    session.activate().expect("Should activate created session");
    assert_eq!(session.state, SessionState::Active);

    // Terminate
    session
        .terminate()
        .expect("Should terminate active session");
    assert_eq!(session.state, SessionState::Terminated);

    // Close
    session.close().expect("Should close terminated session");
    assert_eq!(session.state, SessionState::Closed);

    // Cannot activate closed session
    assert!(session.activate().is_err());
}

#[test]
fn test_approval_state_transitions() {
    let action_hash = ActionHash::from_hex(&"a".repeat(64)).unwrap();
    let decision_id = DecisionId::new_v7();
    let approver = PrincipalId::new("principal:user:admin").unwrap();

    let mut approval = Approval::new(action_hash, decision_id, "Delete database table", None, 300);
    assert_eq!(approval.state, ApprovalState::Pending);

    // Approve
    let mut app_approved = approval.clone();
    app_approved
        .approve(approver.clone())
        .expect("Should approve");
    assert_eq!(app_approved.state, ApprovalState::Approved);
    assert_eq!(app_approved.approver, Some(approver.clone()));

    // Cannot deny after approve
    assert!(app_approved.deny(Some(approver.clone())).is_err());

    // Deny
    let mut app_denied = approval.clone();
    app_denied.deny(Some(approver)).expect("Should deny");
    assert_eq!(app_denied.state, ApprovalState::Denied);

    // Cancel
    approval.cancel().expect("Should cancel");
    assert_eq!(approval.state, ApprovalState::Cancelled);
}

#[test]
fn test_execution_state_transitions() {
    let action_id = ActionId::new_v7();
    let action_hash = ActionHash::from_hex(&"b".repeat(64)).unwrap();
    let lease_id = LeaseId::new_v7();

    let mut exec = Execution::new(
        action_id,
        action_hash,
        ExecutionRoute::Native,
        Some(lease_id),
    );
    assert_eq!(exec.state, ExecutionState::Pending);

    exec.start().expect("Should start execution");
    assert_eq!(exec.state, ExecutionState::Running);

    let result = ExecutionResult::success(b"tool output data", "tool output data");
    exec.complete_success(result)
        .expect("Should complete with success");
    assert_eq!(exec.state, ExecutionState::Succeeded);
    assert!(exec.duration_ms.is_some());

    // Cannot start an already succeeded execution
    assert!(exec.start().is_err());
}

#[test]
fn test_lease_state_transitions() {
    let action_hash = ActionHash::from_hex(&"c".repeat(64)).unwrap();
    let principal = PrincipalId::new("principal:agent-123").unwrap();

    let mut lease = CredentialLease::new(
        action_hash,
        principal,
        CredentialProviderType::GithubApp,
        "gh_app_123",
        "github.com",
        "repo:org/test-repo",
        30,
    );
    assert_eq!(lease.state, LeaseState::Issued);

    lease.consume().expect("Should consume issued lease");
    assert_eq!(lease.state, LeaseState::Consumed);

    // Double consume should fail
    assert!(lease.consume().is_err());
}

#[test]
fn test_resource_uri_validation() {
    let valid_file =
        ResourceUri::parse("file:///workspace/project/main.rs").expect("Valid file uri");
    assert_eq!(valid_file.scheme(), "file");
    assert_eq!(valid_file.path(), "/workspace/project/main.rs");

    let valid_github =
        ResourceUri::parse("github://github.com/relay-security/relay").expect("Valid github uri");
    assert_eq!(valid_github.scheme(), "github");

    // Invalid URIs
    assert!(ResourceUri::parse("").is_err());
    assert!(ResourceUri::parse("no-scheme-path").is_err());
}
