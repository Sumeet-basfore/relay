//! Standard Unix exit codes for Relay CLI and subprocess lifecycle (A007, A010).

/// Relay process exit codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Subprocess terminated normally with code 0; all in-flight receipts flushed.
    Success = 0,
    /// Child MCP subprocess terminated with non-zero exit status or uncaught runtime crash.
    RuntimeError = 1,
    /// Invalid CLI arguments, missing configuration file, or unparseable Cedar policy files.
    ConfigError = 2,
    /// Governed action was denied by Cedar policy.
    PolicyDenied = 3,
    /// Operator rejected action on /dev/tty or aborted approval session.
    ApprovalDenied = 4,
    /// Malformed MCP JSON-RPC frame received from client or child subprocess.
    ProtocolError = 5,
    /// Keyring unavailable, signing key corrupted, or SQLite ledger tampering detected.
    SecurityFailure = 6,
    /// Action requires human approval, but Relay is operating in headless / non-interactive mode.
    ApprovalRequired = 7,
    /// Approval request timed out waiting for operator confirmation.
    ApprovalExpired = 8,
    /// Approval request was cancelled by operator or signal.
    ApprovalCancelled = 9,
}

impl ExitCode {
    pub const EXIT_SUCCESS: i32 = 0;
    pub const EXIT_RUNTIME_ERROR: i32 = 1;
    pub const EXIT_CONFIG_ERROR: i32 = 2;
    pub const EXIT_POLICY_DENIED: i32 = 3;
    pub const EXIT_APPROVAL_DENIED: i32 = 4;
    pub const EXIT_PROTOCOL_ERROR: i32 = 5;
    pub const EXIT_SECURITY_FAILURE: i32 = 6;
    pub const EXIT_APPROVAL_REQUIRED: i32 = 7;
    pub const EXIT_APPROVAL_EXPIRED: i32 = 8;
    pub const EXIT_APPROVAL_CANCELLED: i32 = 9;

    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}
