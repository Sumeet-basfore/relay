use std::fmt;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use relay_domain::error::{ExecutionError, RelayError};

/// Platform sandbox execution mode for MCP subprocesses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformSandboxMode {
    /// Linux Full Enforced Sandbox: unprivileged user & network namespaces (CLONE_NEWUSER | CLONE_NEWNET)
    LinuxEnforcedNetNS,
    /// macOS / Windows: Managed Cooperative Proxy mode via environment variables
    ManagedCooperative,
    /// Platform without sandbox or proxy support
    Unsupported,
}

impl fmt::Display for PlatformSandboxMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinuxEnforcedNetNS => {
                write!(f, "Linux Enforced Network Namespace Sandbox (SI-023)")
            }
            Self::ManagedCooperative => write!(
                f,
                "Managed Cooperative Proxy Mode (HTTP_PROXY / HTTPS_PROXY)"
            ),
            Self::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// Launcher for sandboxed MCP subprocesses
#[derive(Debug, Clone)]
pub struct EgressSandboxLauncher {
    proxy_url: String,
    lease_token: String,
    enforce_linux_netns: bool,
}

impl EgressSandboxLauncher {
    pub fn new(proxy_url: impl Into<String>, lease_token: impl Into<String>) -> Self {
        Self {
            proxy_url: proxy_url.into(),
            lease_token: lease_token.into(),
            enforce_linux_netns: true,
        }
    }

    pub fn with_enforce_netns(mut self, enforce: bool) -> Self {
        self.enforce_linux_netns = enforce;
        self
    }

    /// Detect active platform sandbox mode
    pub fn detect_mode(&self) -> PlatformSandboxMode {
        if cfg!(target_os = "linux") {
            PlatformSandboxMode::LinuxEnforcedNetNS
        } else if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
            PlatformSandboxMode::ManagedCooperative
        } else {
            PlatformSandboxMode::Unsupported
        }
    }

    /// Check if Linux unprivileged user/net namespaces are supported by current kernel
    pub fn is_linux_netns_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Check if /proc/sys/kernel/unprivileged_userns_clone exists and is not 0
            if let Ok(val) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
                if val.trim() == "0" {
                    return false;
                }
            }
            true
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Configure environment variables for proxy redirection
    pub fn inject_proxy_env(&self, cmd: &mut Command) {
        cmd.env("HTTP_PROXY", &self.proxy_url);
        cmd.env("http_proxy", &self.proxy_url);
        cmd.env("HTTPS_PROXY", &self.proxy_url);
        cmd.env("https_proxy", &self.proxy_url);
        cmd.env("ALL_PROXY", &self.proxy_url);
        cmd.env("all_proxy", &self.proxy_url);
        cmd.env("RELAY_PROXY_AUTH", &self.lease_token);
        cmd.env("NO_PROXY", "127.0.0.1,localhost");
        cmd.env("no_proxy", "127.0.0.1,localhost");
    }

    /// Spawn a sandboxed subprocess according to platform capabilities (SI-023, SI-024)
    pub fn spawn(&self, mut cmd: Command) -> Result<Child, RelayError> {
        self.inject_proxy_env(&mut cmd);

        #[cfg(target_os = "linux")]
        {
            if self.enforce_linux_netns {
                let uid = unsafe { libc::getuid() };
                let gid = unsafe { libc::getgid() };

                unsafe {
                    cmd.pre_exec(move || {
                        // Unshare user and network namespaces (SI-023: eliminates raw sockets)
                        let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNET;
                        if libc::unshare(flags) != 0 {
                            let err = std::io::Error::last_os_error();
                            // Fail-closed invariant SI-024: never allow execution without sandbox on Linux
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!(
                                    "Linux sandbox unshare failed (SI-024 fail-closed): {}",
                                    err
                                ),
                            ));
                        }

                        // Map UID and GID inside new user namespace
                        // Write "deny" to setgroups if present
                        let _ = std::fs::write("/proc/self/setgroups", "deny");
                        let _ = std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid));
                        let _ = std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid));

                        Ok(())
                    });
                }

                info!(
                    proxy = %self.proxy_url,
                    mode = %PlatformSandboxMode::LinuxEnforcedNetNS,
                    "Spawning MCP subprocess in Linux Network Namespace Sandbox"
                );
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            info!(
                proxy = %self.proxy_url,
                mode = %PlatformSandboxMode::ManagedCooperative,
                "Spawning MCP subprocess in Managed Cooperative Proxy Mode"
            );
        }

        cmd.spawn().map_err(|e| {
            warn!(error = %e, "Failed to spawn sandboxed subprocess (SI-024 fail-closed)");
            RelayError::Execution(ExecutionError::SandboxSetupFailed(format!(
                "Failed to spawn sandboxed MCP process: {e}"
            )))
        })
    }
}
