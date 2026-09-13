//! `relay run` MCP stdio gateway command.

use crate::cli::RunArgs;
use crate::cli_error::CliError;
use relay_domain::SessionId;
use relay_mcp::{run_gateway, spawn, GatewayConfig, SubprocessConfig};
use tokio::sync::watch;

const RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Execute the MCP gateway wrapping a child MCP server subprocess.
pub async fn execute(args: RunArgs) -> Result<(), CliError> {
    if args.server_command.is_empty() {
        return Err(CliError::ExecutionError(
            "MCP server command is required after '--'".into(),
        ));
    }

    let program = args.server_command[0].clone();
    let child_args = args.server_command[1..].to_vec();

    tracing::info!(
        program = %program,
        arg_count = child_args.len(),
        non_interactive = args.non_interactive,
        "Spawning MCP subprocess"
    );

    let subprocess = spawn(&SubprocessConfig::new(program, child_args, RELAY_VERSION))
        .await
        .map_err(|e| CliError::ExecutionError(e.to_string()))?;

    let session_id = SessionId::new_v7();
    let config = GatewayConfig::with_pass_through(session_id);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let shutdown_task = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("register SIGTERM");
            let mut sigint = signal(SignalKind::interrupt()).expect("register SIGINT");
            tokio::select! {
                _ = sigterm.recv() => {},
                _ = sigint.recv() => {},
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }

        let _ = shutdown_tx.send(true);
    });

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let exit_status = run_gateway(stdin, stdout, subprocess, config, shutdown_rx)
        .await
        .map_err(|e| CliError::ExecutionError(e.to_string()))?;

    shutdown_task.abort();

    let code = exit_status.child_exit_code.unwrap_or(0);
    std::process::exit(code);
}
