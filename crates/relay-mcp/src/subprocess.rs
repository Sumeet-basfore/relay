//! MCP child subprocess spawning with environment isolation.

use crate::env::apply_sanitized_env;
use relay_domain::ExecutionError;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Default startup timeout before declaring a child subprocess unresponsive.
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Architecture-defined shutdown grace period before escalating from SIGTERM to SIGKILL (A007).
pub const DEFAULT_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_millis(500);

/// Configuration for spawning an MCP server subprocess.
#[derive(Debug, Clone)]
pub struct SubprocessConfig {
    pub program: String,
    pub args: Vec<String>,
    pub relay_version: String,
    pub startup_timeout: Duration,
    pub shutdown_grace_period: Duration,
}

impl SubprocessConfig {
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        relay_version: impl Into<String>,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            relay_version: relay_version.into(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            shutdown_grace_period: DEFAULT_SHUTDOWN_GRACE_PERIOD,
        }
    }
}

/// A running MCP child subprocess with piped stdio.
pub struct McpSubprocess {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
}

impl McpSubprocess {
    pub fn stdin_mut(&mut self) -> &mut ChildStdin {
        &mut self.stdin
    }

    pub fn stdout_mut(&mut self) -> &mut ChildStdout {
        &mut self.stdout
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, ExecutionError> {
        self.child
            .try_wait()
            .map_err(|e| ExecutionError::SubprocessFailed {
                command: "child".into(),
                reason: e.to_string(),
            })
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, ExecutionError> {
        self.child
            .wait()
            .await
            .map_err(|e| ExecutionError::SubprocessFailed {
                command: self.child.id().map(|id| id.to_string()).unwrap_or_default(),
                reason: e.to_string(),
            })
    }

    pub async fn kill(&mut self) -> Result<(), ExecutionError> {
        self.child
            .kill()
            .await
            .map_err(|e| ExecutionError::SubprocessFailed {
                command: "kill".into(),
                reason: e.to_string(),
            })
    }

    /// Architecture-defined graceful shutdown sequence:
    /// SIGTERM / requested shutdown
    ///         ↓
    /// send termination request
    ///         ↓
    /// grace period (default 500ms per A007)
    ///         ↓
    /// SIGKILL if still alive
    pub async fn terminate_gracefully(
        &mut self,
        grace_period: Duration,
    ) -> Result<Option<std::process::ExitStatus>, ExecutionError> {
        terminate_child_gracefully(&mut self.child, grace_period).await
    }
}

/// Standalone graceful child process termination function.
pub async fn terminate_child_gracefully(
    child: &mut Child,
    grace_period: Duration,
) -> Result<Option<std::process::ExitStatus>, ExecutionError> {
    // 1. If child has already exited, reap and return status immediately
    if let Ok(Some(status)) = child.try_wait() {
        return Ok(Some(status));
    }

    // 2. Send termination request (SIGTERM on Unix)
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = child.start_kill();
    }

    // 3. Wait for child to exit within the architecture-defined grace period
    match tokio::time::timeout(grace_period, child.wait()).await {
        Ok(Ok(status)) => Ok(Some(status)),
        Ok(Err(e)) => Err(ExecutionError::SubprocessFailed {
            command: "child".into(),
            reason: e.to_string(),
        }),
        Err(_) => {
            // 4. Grace period expired; child is still alive. Escalate to SIGKILL
            tracing::warn!(
                grace_period_ms = grace_period.as_millis(),
                "Child subprocess did not exit within grace period; escalating to SIGKILL"
            );
            let _ = child.kill().await;
            let status = child.wait().await.ok();
            Ok(status)
        }
    }
}

/// Spawn the MCP server without shell interpretation.
pub async fn spawn(config: &SubprocessConfig) -> Result<McpSubprocess, ExecutionError> {
    if config.program.trim().is_empty() {
        return Err(ExecutionError::SubprocessFailed {
            command: String::new(),
            reason: "MCP server command cannot be empty".into(),
        });
    }

    let mut cmd = Command::new(&config.program);
    cmd.args(&config.args);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    // Guarantee child is killed if the Rust Child struct is dropped (prevents orphans)
    cmd.kill_on_drop(true);

    // On Linux, instruct the kernel to deliver SIGKILL to the child if Relay dies violently
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    apply_sanitized_env(&mut cmd, &config.relay_version);

    let mut child = cmd.spawn().map_err(|e| ExecutionError::SubprocessFailed {
        command: config.program.clone(),
        reason: e.to_string(),
    })?;

    // Check if child exited immediately upon spawn (e.g. fatal exec or missing entrypoint)
    if let Ok(Some(status)) = child.try_wait() {
        return Err(ExecutionError::SubprocessFailed {
            command: config.program.clone(),
            reason: format!("child process exited immediately with {status}"),
        });
    }

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ExecutionError::SubprocessFailed {
            command: config.program.clone(),
            reason: "failed to open child stdin pipe".into(),
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecutionError::SubprocessFailed {
            command: config.program.clone(),
            reason: "failed to open child stdout pipe".into(),
        })?;

    Ok(McpSubprocess {
        child,
        stdin,
        stdout,
    })
}

/// Type alias for agent-facing transport streams.
pub type AgentReader = tokio::io::Stdin;
pub type AgentWriter = tokio::io::Stdout;
