//! Interactive human approval provider using /dev/tty (A003, A004, A007).

use async_trait::async_trait;
use chrono::Utc;
use relay_domain::{Approval, ApprovalError, ApprovalMechanism, ApprovalProvider, PrincipalId};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::approval::prompt::{render_approval_prompt, render_details_view};

/// Source / Destination for interactive TTY I/O
#[derive(Clone)]
pub enum TtyTarget {
    /// Standard OS device file (e.g. /dev/tty on Unix)
    DevicePath(PathBuf),
    /// Injected mock streams for deterministic testing
    MockStreams {
        input: Arc<Mutex<Box<dyn tokio::io::AsyncBufRead + Send + Unpin>>>,
        output: Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>>,
    },
}

/// Configuration for the interactive TTY provider
#[derive(Clone)]
pub struct TtyConfig {
    pub target: TtyTarget,
    pub approver_principal: PrincipalId,
    pub fallback_to_headless_on_missing_tty: bool,
}

impl Default for TtyConfig {
    fn default() -> Self {
        #[cfg(unix)]
        let path = PathBuf::from("/dev/tty");
        #[cfg(windows)]
        let path = PathBuf::from(r"\\.\CONIN$");
        #[cfg(not(any(unix, windows)))]
        let path = PathBuf::from("/dev/tty");

        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "operator".to_string());
        let approver_principal = PrincipalId::new(format!("principal:user:local:{username}"))
            .unwrap_or_else(|_| PrincipalId::new("principal:user:local:operator").unwrap());

        Self {
            target: TtyTarget::DevicePath(path),
            approver_principal,
            fallback_to_headless_on_missing_tty: false,
        }
    }
}

/// Interactive TTY Approval Provider enforcing SI-004
pub struct TtyApprovalProvider {
    config: TtyConfig,
    /// Concurrency lock ensuring concurrent approval requests are serialized cleanly
    interaction_lock: Arc<Mutex<()>>,
}

impl TtyApprovalProvider {
    pub fn new(config: TtyConfig) -> Self {
        Self {
            config,
            interaction_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Creates provider pointing to standard /dev/tty
    pub fn default_tty() -> Self {
        Self::new(TtyConfig::default())
    }

    /// Creates provider with custom mock streams for testing
    pub fn with_mock_streams<R, W>(reader: R, writer: W, approver: Option<PrincipalId>) -> Self
    where
        R: tokio::io::AsyncBufRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let approver_principal = approver
            .unwrap_or_else(|| PrincipalId::new("principal:user:local:test_operator").unwrap());
        Self {
            config: TtyConfig {
                target: TtyTarget::MockStreams {
                    input: Arc::new(Mutex::new(Box::new(reader))),
                    output: Arc::new(Mutex::new(Box::new(writer))),
                },
                approver_principal,
                fallback_to_headless_on_missing_tty: false,
            },
            interaction_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Tests whether the controlling terminal is available for opening
    pub fn is_tty_available(&self) -> bool {
        match &self.config.target {
            TtyTarget::DevicePath(path) => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .is_ok(),
            TtyTarget::MockStreams { .. } => true,
        }
    }
}

#[async_trait]
impl ApprovalProvider for TtyApprovalProvider {
    async fn request_approval(&self, approval: &mut Approval) -> Result<(), ApprovalError> {
        // Enforce SI-004: Mutex serialization ensures no concurrent prompt interleaving
        let _guard = self.interaction_lock.lock().await;

        // Check freshness / expiration before displaying
        if approval.is_expired() {
            let _ = approval.expire();
            return Err(ApprovalError::TimedOut { timeout_secs: 0 });
        }

        approval.mechanism = Some(ApprovalMechanism::TtyInteractive);

        match &self.config.target {
            TtyTarget::DevicePath(path) => {
                #[cfg(unix)]
                let device_str = path.to_string_lossy().to_string();
                #[cfg(not(unix))]
                let device_str = "CONIN$".to_string();

                approval.terminal_device = Some(device_str);

                // Attempt to open device file
                let read_file = match tokio::fs::OpenOptions::new().read(true).open(path).await {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(
                            path = ?path,
                            error = %e,
                            "Failed to open controlling terminal (/dev/tty)"
                        );
                        if self.config.fallback_to_headless_on_missing_tty {
                            let _ = approval.deny(
                                None,
                                Some("TTY unavailable; failing closed in headless mode".into()),
                            );
                            approval.mechanism = Some(ApprovalMechanism::HeadlessGate);
                            return Err(ApprovalError::NonInteractiveMode);
                        } else {
                            let _ = approval.deny(None, Some(format!("TTY unavailable: {e}")));
                            return Err(ApprovalError::TtyUnavailable(e.to_string()));
                        }
                    }
                };

                let write_file = match tokio::fs::OpenOptions::new().write(true).open(path).await {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = approval.deny(None, Some(format!("TTY output unavailable: {e}")));
                        return Err(ApprovalError::TtyUnavailable(e.to_string()));
                    }
                };

                let mut reader = BufReader::new(read_file);
                let mut writer = write_file;

                self.run_prompt_loop(approval, &mut reader, &mut writer)
                    .await
            }
            TtyTarget::MockStreams { input, output } => {
                approval.terminal_device = Some("/dev/mock_tty".to_string());
                let mut in_guard = input.lock().await;
                let mut out_guard = output.lock().await;

                self.run_prompt_loop(approval, &mut **in_guard, &mut **out_guard)
                    .await
            }
        }
    }
}

impl TtyApprovalProvider {
    async fn run_prompt_loop(
        &self,
        approval: &mut Approval,
        reader: &mut (dyn tokio::io::AsyncBufRead + Unpin + Send),
        writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    ) -> Result<(), ApprovalError> {
        loop {
            let now = Utc::now();
            if now > approval.expires_at {
                let _ = approval.expire();
                let _ = writer
                    .write_all(b"\n\x1b[31mApproval request timed out.\x1b[0m\n")
                    .await;
                let _ = writer.flush().await;
                return Err(ApprovalError::TimedOut { timeout_secs: 0 });
            }

            let remaining_secs = (approval.expires_at.timestamp() - now.timestamp()).max(0) as u64;
            let remaining_duration = std::time::Duration::from_secs(remaining_secs);

            let prompt_text = render_approval_prompt(approval);
            if let Err(e) = writer.write_all(prompt_text.as_bytes()).await {
                let _ = approval.cancel();
                return Err(ApprovalError::Cancelled(format!(
                    "Failed to write to terminal: {e}"
                )));
            }
            let _ = writer.flush().await;

            let mut input_line = String::new();
            let read_result =
                tokio::time::timeout(remaining_duration, reader.read_line(&mut input_line)).await;

            match read_result {
                Ok(Ok(0)) => {
                    // EOF encountered
                    let _ = approval.cancel();
                    approval.denial_reason = Some("EOF on terminal input".into());
                    let _ = writer
                        .write_all(
                            b"\n\x1b[33mApproval cancelled (EOF received on terminal).\x1b[0m\n\n",
                        )
                        .await;
                    let _ = writer.flush().await;
                    return Err(ApprovalError::Cancelled("EOF on terminal input".into()));
                }
                Ok(Ok(_)) => {
                    let cmd = input_line.trim().to_lowercase();
                    match cmd.as_str() {
                        "y" | "yes" => {
                            if let Err(e) = approval.approve(self.config.approver_principal.clone())
                            {
                                return Err(ApprovalError::Cancelled(e.to_string()));
                            }
                            let _ = writer
                                .write_all(
                                    b"\n\x1b[32m[APPROVED] Action approved by operator.\x1b[0m\n\n",
                                )
                                .await;
                            let _ = writer.flush().await;
                            tracing::info!(
                                action_hash = %approval.action_hash.to_hex(),
                                approver = %self.config.approver_principal,
                                "Operator approved action via /dev/tty"
                            );
                            return Ok(());
                        }
                        "n" | "no" | "" => {
                            let reason = "Action denied by operator on /dev/tty".to_string();
                            let _ = approval.deny(
                                Some(self.config.approver_principal.clone()),
                                Some(reason.clone()),
                            );
                            let _ = writer
                                .write_all(
                                    b"\n\x1b[31m[DENIED] Action denied by operator.\x1b[0m\n\n",
                                )
                                .await;
                            let _ = writer.flush().await;
                            tracing::warn!(
                                action_hash = %approval.action_hash.to_hex(),
                                "Operator denied action via /dev/tty"
                            );
                            return Err(ApprovalError::DeniedByHuman(reason));
                        }
                        "d" | "details" => {
                            let details = render_details_view(approval);
                            let _ = writer.write_all(details.as_bytes()).await;
                            let _ = writer.flush().await;
                            // Loop back and re-render prompt
                            continue;
                        }
                        "q" | "quit" | "cancel" | "abort" => {
                            let _ = approval.cancel();
                            approval.denial_reason = Some("Cancelled by operator via TTY".into());
                            let _ = writer
                                .write_all(b"\n\x1b[33m[CANCELLED] Approval cancelled by operator.\x1b[0m\n\n")
                                .await;
                            let _ = writer.flush().await;
                            tracing::warn!(
                                action_hash = %approval.action_hash.to_hex(),
                                "Operator cancelled approval session on /dev/tty"
                            );
                            return Err(ApprovalError::Cancelled(
                                "Operator cancelled approval".into(),
                            ));
                        }
                        _ => {
                            let _ = writer
                                .write_all(b"\n\x1b[33mInvalid selection. Enter 'y' to approve, 'n' to deny, 'd' for details, or 'q' to cancel.\x1b[0m\n")
                                .await;
                            let _ = writer.flush().await;
                            // Loop back and re-prompt
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    let _ = approval.cancel();
                    approval.denial_reason = Some(format!("Terminal read error: {e}"));
                    return Err(ApprovalError::Cancelled(format!(
                        "Terminal read error: {e}"
                    )));
                }
                Err(_) => {
                    // Timeout occurred
                    let _ = approval.expire();
                    approval.denial_reason = Some("Approval timed out".into());
                    let _ = writer
                        .write_all(b"\n\x1b[31mApproval request timed out.\x1b[0m\n\n")
                        .await;
                    let _ = writer.flush().await;
                    tracing::warn!(
                        action_hash = %approval.action_hash.to_hex(),
                        "Approval request timed out on /dev/tty"
                    );
                    return Err(ApprovalError::TimedOut {
                        timeout_secs: remaining_duration.as_secs(),
                    });
                }
            }
        }
    }
}
