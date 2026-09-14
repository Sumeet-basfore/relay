use relay_domain::{
    ActionHash, Approval, ApprovalMechanism, ApprovalProvider, ApprovalState, DecisionId, Digest,
    PrincipalId,
};
use relay_mcp::approval::tty::TtyApprovalProvider;
use serde_json::json;

fn make_dummy_approval(id_str: &str) -> Approval {
    Approval::new_with_context(
        ActionHash::compute(id_str.as_bytes()),
        DecisionId::new_v7(),
        "Create pull request on repo",
        None,
        60,
        "github.create_pull_request",
        PrincipalId::new("principal:agent:test-agent").unwrap(),
        "owner/repo",
        Digest::from_bytes([0x01; 32]),
        ApprovalMechanism::TtyInteractive,
    )
    .with_parameters_preview(json!({"title": "Test PR", "secret_token": "ghp_secret"}))
}

#[tokio::test]
async fn test_tty_approval_approve() {
    let input_bytes = b"y\n";
    let (reader, writer) = (tokio::io::BufReader::new(&input_bytes[..]), Vec::new());
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-1");
    let result = provider.request_approval(&mut approval).await;

    assert!(result.is_ok());
    assert_eq!(approval.state, ApprovalState::Approved);
    assert_eq!(approval.mechanism, Some(ApprovalMechanism::TtyInteractive));
    assert_eq!(
        approval.approver,
        Some(PrincipalId::new("principal:user:local:test_operator").unwrap())
    );
}

#[tokio::test]
async fn test_tty_approval_deny() {
    let input_bytes = b"n\n";
    let (reader, writer) = (tokio::io::BufReader::new(&input_bytes[..]), Vec::new());
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-2");
    let result = provider.request_approval(&mut approval).await;

    assert!(result.is_err());
    assert_eq!(approval.state, ApprovalState::Denied);
    assert_eq!(approval.mechanism, Some(ApprovalMechanism::TtyInteractive));
    assert_eq!(
        approval.denial_reason,
        Some("Action denied by operator on /dev/tty".into())
    );
}

#[tokio::test]
async fn test_tty_approval_cancel() {
    let input_bytes = b"q\n";
    let (reader, writer) = (tokio::io::BufReader::new(&input_bytes[..]), Vec::new());
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-3");
    let result = provider.request_approval(&mut approval).await;

    assert!(result.is_err());
    assert_eq!(approval.state, ApprovalState::Cancelled);
    assert_eq!(
        approval.denial_reason,
        Some("Cancelled by operator via TTY".into())
    );
}

#[tokio::test]
async fn test_tty_approval_details_then_approve() {
    let input_bytes = b"d\ny\n";
    let (reader, writer) = (tokio::io::BufReader::new(&input_bytes[..]), Vec::new());
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-4");
    let result = provider.request_approval(&mut approval).await;

    assert!(result.is_ok());
    assert_eq!(approval.state, ApprovalState::Approved);
}

#[tokio::test]
async fn test_tty_approval_invalid_input_retry() {
    let input_bytes = b"invalid_option\ny\n";
    let (reader, writer) = (tokio::io::BufReader::new(&input_bytes[..]), Vec::new());
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-5");
    let result = provider.request_approval(&mut approval).await;

    assert!(result.is_ok());
    assert_eq!(approval.state, ApprovalState::Approved);
}

#[tokio::test]
async fn test_tty_approval_eof_denies() {
    let input_bytes = b"";
    let (reader, writer) = (tokio::io::BufReader::new(&input_bytes[..]), Vec::new());
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-6");
    let result = provider.request_approval(&mut approval).await;

    assert!(result.is_err());
    assert_eq!(approval.state, ApprovalState::Cancelled);
    assert_eq!(approval.denial_reason, Some("EOF on terminal input".into()));
}

#[tokio::test]
async fn test_tty_approval_timeout() {
    let (client_read, _client_write) = tokio::io::duplex(64);
    let writer = Vec::new();

    let reader = tokio::io::BufReader::new(client_read);
    let provider = TtyApprovalProvider::with_mock_streams(reader, writer, None);

    let mut approval = make_dummy_approval("test-7");
    approval.expires_at = chrono::Utc::now() + chrono::Duration::seconds(1);

    let result = provider.request_approval(&mut approval).await;
    assert!(result.is_err());
    assert_eq!(approval.state, ApprovalState::Expired);
    assert_eq!(approval.denial_reason, Some("Approval timed out".into()));
}
