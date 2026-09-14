//! Headless Approval Gate (fail-closed) (A003, A004, A007).

use async_trait::async_trait;
use relay_domain::{Approval, ApprovalError, ApprovalMechanism, ApprovalProvider};

/// Deterministic Headless Gate that fails closed whenever human approval is required
#[derive(Debug, Default, Clone, Copy)]
pub struct HeadlessApprovalGate {
    pub exit_code_on_block: i32,
}

impl HeadlessApprovalGate {
    pub fn new() -> Self {
        Self {
            exit_code_on_block: relay_domain::ExitCode::EXIT_APPROVAL_REQUIRED,
        }
    }
}

#[async_trait]
impl ApprovalProvider for HeadlessApprovalGate {
    async fn request_approval(&self, approval: &mut Approval) -> Result<(), ApprovalError> {
        tracing::warn!(
            action_hash = %approval.action_hash.to_hex(),
            "Action requires step-up human approval, but Relay is running in headless mode (no TTY). Blocking execution."
        );

        let _ = approval.deny(
            None,
            Some("Headless mode: action requires human approval but no interactive terminal is present".to_string()),
        );
        approval.mechanism = Some(ApprovalMechanism::HeadlessGate);

        Err(ApprovalError::NonInteractiveMode)
    }
}
