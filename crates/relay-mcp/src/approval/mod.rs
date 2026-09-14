//! Approval Provider subsystem for interactive TTY confirmation and headless gating (B011).

pub mod headless;
pub mod prompt;
pub mod tty;

pub use headless::HeadlessApprovalGate;
pub use prompt::{redact_sensitive_value, render_approval_prompt, render_details_view};
pub use tty::{TtyApprovalProvider, TtyConfig, TtyTarget};

// Re-export core domain types for convenience
pub use relay_domain::{
    Approval, ApprovalError, ApprovalMechanism, ApprovalProvider, ApprovalRequest, ApprovalState,
    HeadlessApprovalProvider, MockApprovalProvider,
};
