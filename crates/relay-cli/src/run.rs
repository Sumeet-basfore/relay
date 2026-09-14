//! `relay run` MCP stdio gateway command.

use crate::cli::RunArgs;
use crate::cli_error::CliError;
use relay_domain::SessionId;
use relay_mcp::{run_gateway, spawn, GatewayConfig, SubprocessConfig};
use tokio::sync::watch;

const RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Execute the MCP gateway wrapping a child MCP server subprocess.
pub async fn execute(
    args: RunArgs,
    relay_config: &crate::config::RelayConfig,
) -> Result<(), CliError> {
    if args.server_command.is_empty() {
        return Err(CliError::ConfigError(
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

    let approval_provider: std::sync::Arc<dyn relay_domain::ApprovalProvider> = if args
        .non_interactive
    {
        std::sync::Arc::new(relay_mcp::HeadlessApprovalGate::new())
    } else {
        let tty_provider = relay_mcp::TtyApprovalProvider::default_tty();
        if tty_provider.is_tty_available() {
            std::sync::Arc::new(tty_provider)
        } else {
            tracing::warn!(
                "No interactive TTY detected on controlling terminal; falling back to headless fail-closed approval gate"
            );
            std::sync::Arc::new(relay_mcp::HeadlessApprovalGate::new())
        }
    };

    let session_id = SessionId::new_v7();
    let policy_dir_opt = args.policy_dir.as_ref().or_else(|| {
        if relay_config.policy.policy_dir.exists() {
            Some(&relay_config.policy.policy_dir)
        } else {
            None
        }
    });

    let engine: std::sync::Arc<dyn relay_domain::PolicyEngine> = if let Some(policy_dir) =
        policy_dir_opt
    {
        let e = if policy_dir.is_dir() {
            relay_policy::CedarPolicyEngine::from_dir(policy_dir, None)
        } else {
            relay_policy::CedarPolicyEngine::from_file(policy_dir, None)
        }
        .map_err(|err| CliError::ConfigError(format!("Failed to load Cedar policies: {}", err)))?;
        std::sync::Arc::new(e)
    } else {
        let e = relay_policy::CedarPolicyEngine::default_engine().map_err(|err| {
            CliError::ConfigError(format!("Failed to load default Cedar policies: {}", err))
        })?;
        std::sync::Arc::new(e)
    };

    let ledger_path = &relay_config.storage.ledger_path;
    let ledger = relay_ledger::SqliteLedger::open(ledger_path).map_err(|e| {
        CliError::StorageError(format!(
            "Failed to open ledger database at '{}': {e}",
            ledger_path.display()
        ))
    })?;

    use relay_domain::ReceiptSigner;
    let signer = load_or_generate_signer()?;
    let pubkey_hex = hex::encode(signer.export_public_key());
    let _ = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await;

    let credential_broker = std::sync::Arc::new(relay_credentials::JitCredentialBroker::default());
    let fs_connector = std::sync::Arc::new(relay_connectors::FilesystemConnector::new(
        relay_connectors::FsConnectorConfig::new("."),
    ));
    let github_connector = relay_connectors::GitHubConnector::default_production()
        .ok()
        .map(std::sync::Arc::new);
    let postgres_connector = relay_connectors::PostgresConnector::default_production()
        .ok()
        .map(std::sync::Arc::new);

    let mut runner_builder = relay_connectors::GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(approval_provider)
        .credential_broker(credential_broker)
        .receipt_signer(signer)
        .ledger(std::sync::Arc::new(ledger))
        .fs_connector(fs_connector);

    if let Some(gh) = github_connector {
        runner_builder = runner_builder.github_connector(gh);
    }
    if let Some(pg) = postgres_connector {
        runner_builder = runner_builder.postgres_connector(pg);
    }

    let runner = runner_builder
        .build()
        .map_err(|e| CliError::ExecutionError(e.to_string()))?;

    let interceptor = std::sync::Arc::new(
        crate::governed_interceptor::GovernedToolCallInterceptor::new(std::sync::Arc::new(runner)),
    );

    let gateway_config = GatewayConfig::new(
        session_id,
        interceptor,
        std::sync::Arc::new(relay_canonical::ActionCanonicalizer::default()),
    );

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

    let exit_status = run_gateway(stdin, stdout, subprocess, gateway_config, shutdown_rx)
        .await
        .map_err(|e| CliError::ExecutionError(e.to_string()))?;

    shutdown_task.abort();

    let code = exit_status.child_exit_code.unwrap_or(0);
    std::process::exit(code);
}

fn load_or_generate_signer(
) -> Result<std::sync::Arc<relay_receipts::Ed25519ReceiptSigner>, CliError> {
    // 1. Check environment variable for hex private key
    if let Ok(key_hex) = std::env::var("RELAY_SIGNING_KEY") {
        if !key_hex.trim().is_empty() {
            let signer =
                relay_receipts::Ed25519ReceiptSigner::from_hex(&key_hex, "relay-env-ed25519-v1")
                    .map_err(|e| {
                        CliError::SecurityFailure(format!(
                            "Failed to load signing key from RELAY_SIGNING_KEY: {e}"
                        ))
                    })?;
            return Ok(std::sync::Arc::new(signer));
        }
    }

    // 2. Check environment variable for key file path
    if let Ok(key_path) = std::env::var("RELAY_SIGNING_KEY_PATH") {
        let p = std::path::Path::new(&key_path);
        let signer = relay_receipts::Ed25519ReceiptSigner::from_file(p, "relay-file-ed25519-v1")
            .map_err(|e| {
                CliError::SecurityFailure(format!(
                    "Failed to load signing key from '{key_path}': {e}"
                ))
            })?;
        return Ok(std::sync::Arc::new(signer));
    }

    // 3. Check ~/.config/relay/signing_key.seed
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let default_key_path =
        std::path::PathBuf::from(format!("{home}/.config/relay/signing_key.seed"));
    if default_key_path.exists() {
        let signer = relay_receipts::Ed25519ReceiptSigner::from_file(
            &default_key_path,
            "relay-local-ed25519-v1",
        )
        .map_err(|e| {
            CliError::SecurityFailure(format!(
                "Failed to load signing key from default location: {e}"
            ))
        })?;
        return Ok(std::sync::Arc::new(signer));
    }

    // 4. Development mode fallback: generate ephemeral key and log warning
    tracing::warn!(
        "No production Ed25519 signing key found in RELAY_SIGNING_KEY, RELAY_SIGNING_KEY_PATH, or ~/.config/relay/signing_key.seed; generating ephemeral development identity 'relay-dev-ed25519-v1'"
    );
    Ok(std::sync::Arc::new(
        relay_receipts::Ed25519ReceiptSigner::generate("relay-dev-ed25519-v1"),
    ))
}
