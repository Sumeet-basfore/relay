use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{watch, RwLock};

use crate::cli::UiArgs;
use crate::cli_error::CliError;
use crate::config::RelayConfig;
use crate::ui::{SessionManager, UiServer, UiState};

/// Execute the `relay ui` Local Security Console command
pub async fn execute(args: UiArgs, config: &RelayConfig) -> Result<(), CliError> {
    // 1. Strict loopback binding enforcement
    let host_ip: IpAddr = args
        .host
        .parse()
        .map_err(|e| CliError::ConfigError(format!("Invalid host IP '{}': {e}", args.host)))?;

    if !host_ip.is_loopback() {
        return Err(CliError::SecurityFailure(format!(
            "Refusing to bind Relay Security Console to non-loopback address '{}'. Only 127.0.0.1 loopback is permitted.",
            args.host
        )));
    }

    let bind_addr = SocketAddr::new(host_ip, args.port);

    // 2. Initialize Session Manager with ephemeral bootstrap token
    let session_manager = Arc::new(RwLock::new(SessionManager::new(args.token.clone())));
    let bootstrap_token = {
        let sm = session_manager.read().await;
        sm.bootstrap_token().to_string()
    };

    // 3. Initialize Policy Engine
    let policy_dir_opt = if config.policy.policy_dir.exists() {
        Some(&config.policy.policy_dir)
    } else {
        None
    };

    let policy_engine: Arc<dyn relay_domain::PolicyEngine> = if let Some(dir) = policy_dir_opt {
        let e = if dir.is_dir() {
            relay_policy::CedarPolicyEngine::from_dir(dir, None)
        } else {
            relay_policy::CedarPolicyEngine::from_file(dir, None)
        }
        .map_err(|err| CliError::ConfigError(format!("Failed to load Cedar policies: {err}")))?;
        Arc::new(e)
    } else {
        let e = relay_policy::CedarPolicyEngine::default_engine().map_err(|err| {
            CliError::ConfigError(format!("Failed to load default Cedar policies: {err}"))
        })?;
        Arc::new(e)
    };

    // 4. Open SQLite Ledger
    let ledger_path = &config.storage.ledger_path;
    let ledger = relay_ledger::SqliteLedger::open(ledger_path).map_err(|e| {
        CliError::StorageError(format!(
            "Failed to open ledger database at '{}': {e}",
            ledger_path.display()
        ))
    })?;

    // 5. Load or generate signing identity to obtain verifying public key
    let (signing_key_id, signer_pubkey) = load_signing_identity()?;

    // 6. Assemble UI state
    let state = UiState {
        session_manager,
        config: config.clone(),
        ledger: Arc::new(ledger),
        policy_engine: Arc::new(RwLock::new(policy_engine)),
        signing_key_id,
        signer_pubkey,
        port: args.port,
    };

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

    let console_url = format!(
        "http://{}:{}/?token={}",
        args.host, args.port, bootstrap_token
    );

    println!("============================================================");
    println!(" Relay Local Security Console (CR002)");
    println!("============================================================");
    println!(" Status:       Active & Protected");
    println!(" Console URL:  {console_url}");
    println!(" Binding:      {} (Loopback only)", bind_addr);
    println!(" Session Auth: CLI-Issued Ephemeral Token (Idle TTL 15m)");
    println!(" Origin Check: Strict (127.0.0.1 / localhost)");
    println!(" Telemetry:    Zero Outbound Data (100% Localhost)");
    println!("============================================================");
    println!("Press Ctrl+C to terminate the console.");

    // Optionally launch browser
    if !args.no_browser {
        let url_to_open = console_url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("xdg-open")
                    .arg(&url_to_open)
                    .spawn();
            }
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&url_to_open).spawn();
            }
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "start", &url_to_open])
                    .spawn();
            }
        });
    }

    let server = UiServer::new(state, bind_addr);
    server.run(shutdown_rx).await?;

    shutdown_task.abort();
    println!("\nRelay Security Console terminated cleanly.");
    Ok(())
}

fn load_signing_identity() -> Result<(String, Option<[u8; 32]>), CliError> {
    use relay_domain::ReceiptSigner;

    let to_arr = |vec: Vec<u8>| -> Option<[u8; 32]> {
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            Some(arr)
        } else {
            None
        }
    };

    if let Ok(key_hex) = std::env::var("RELAY_SIGNING_KEY") {
        if !key_hex.trim().is_empty() {
            if let Ok(signer) =
                relay_receipts::Ed25519ReceiptSigner::from_hex(&key_hex, "relay-env-ed25519-v1")
            {
                return Ok((
                    "relay-env-ed25519-v1".to_string(),
                    to_arr(signer.export_public_key()),
                ));
            }
        }
    }

    if let Ok(key_path) = std::env::var("RELAY_SIGNING_KEY_PATH") {
        let p = std::path::Path::new(&key_path);
        if let Ok(signer) =
            relay_receipts::Ed25519ReceiptSigner::from_file(p, "relay-file-ed25519-v1")
        {
            return Ok((
                "relay-file-ed25519-v1".to_string(),
                to_arr(signer.export_public_key()),
            ));
        }
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let default_key_path =
        std::path::PathBuf::from(format!("{home}/.config/relay/signing_key.seed"));
    if default_key_path.exists() {
        if let Ok(signer) = relay_receipts::Ed25519ReceiptSigner::from_file(
            &default_key_path,
            "relay-local-ed25519-v1",
        ) {
            return Ok((
                "relay-local-ed25519-v1".to_string(),
                to_arr(signer.export_public_key()),
            ));
        }
    }

    // Ephemeral identity for console verifications
    let ephemeral = relay_receipts::Ed25519ReceiptSigner::generate("relay-dev-ed25519-v1");
    Ok((
        "relay-dev-ed25519-v1".to_string(),
        to_arr(ephemeral.export_public_key()),
    ))
}
