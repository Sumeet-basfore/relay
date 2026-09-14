use clap::Parser;

use relay_cli::cli::{Cli, Commands, PolicySubcommands, SecretSubcommands};
use relay_cli::cli_error::CliError;
use relay_cli::config::RelayConfig;
use relay_cli::{doctor, logging, receipt_cmd, run, ui_cmd, verify_cmd};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize structured logging strictly directed to stderr
    logging::init_logging(cli.verbose, cli.quiet, cli.json);

    // Load configuration
    let config = match RelayConfig::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Error: {err}");
            std::process::exit(err.exit_code().as_i32());
        }
    };

    if let Err(err) = run_app(cli, config).await {
        let exit_code = err.exit_code();
        eprintln!("Error: {err}");
        std::process::exit(exit_code.as_i32());
    }
}

async fn run_app(cli: Cli, config: RelayConfig) -> Result<(), CliError> {
    match cli.command {
        Commands::Run(args) => {
            run::execute(args, &config).await?;
            Ok(())
        }
        Commands::Ui(args) => {
            ui_cmd::execute(args, &config).await?;
            Ok(())
        }
        Commands::Policy(args) => match args.command {
            PolicySubcommands::Validate { path } => {
                let schema = relay_policy::schema::default_schema()
                    .map_err(|e| CliError::ExecutionError(e.to_string()))?;
                let (policies, digest): (
                    relay_policy::cedar_policy::PolicySet,
                    relay_domain::Digest,
                ) = match path {
                    Some(p) => {
                        if p.is_dir() {
                            relay_policy::loader::PolicyLoader::load_from_dir(&p, &schema)
                                .map_err(|e| CliError::ExecutionError(e.to_string()))?
                        } else {
                            relay_policy::loader::PolicyLoader::load_from_file(&p, &schema)
                                .map_err(|e| CliError::ExecutionError(e.to_string()))?
                        }
                    }
                    None => relay_policy::loader::PolicyLoader::load_from_str(
                        relay_policy::loader::RELAY_DEFAULT_POLICIES,
                        &schema,
                    )
                    .map_err(|e| CliError::ExecutionError(e.to_string()))?,
                };
                let count = policies.policies().count();
                println!("=== Cedar Policy Engine Validation ===");
                println!("Status        : VALID (Passed Strict Schema Conformity)");
                println!("Policy Count  : {count}");
                println!("Policy Digest : {digest}");
                Ok(())
            }
            PolicySubcommands::Test { fixtures } => {
                tracing::info!(fixtures = ?fixtures, "Testing Cedar policies");
                Err(CliError::NotImplemented(
                    "relay policy test is scheduled for a future milestone".to_string(),
                ))
            }
        },
        Commands::Secret(args) => match args.command {
            SecretSubcommands::Set { key, .. } => {
                tracing::info!(key = %key, "Setting secret in keyring");
                Err(CliError::NotImplemented(
                    "relay secret set is scheduled for a future milestone".to_string(),
                ))
            }
            SecretSubcommands::Get { key } => {
                tracing::info!(key = %key, "Querying secret in keyring");
                Err(CliError::NotImplemented(
                    "relay secret get is scheduled for a future milestone".to_string(),
                ))
            }
            SecretSubcommands::List => {
                tracing::info!("Listing secrets in keyring");
                Err(CliError::NotImplemented(
                    "relay secret list is scheduled for a future milestone".to_string(),
                ))
            }
            SecretSubcommands::Delete { key } => {
                tracing::info!(key = %key, "Deleting secret from keyring");
                Err(CliError::NotImplemented(
                    "relay secret delete is scheduled for a future milestone".to_string(),
                ))
            }
        },
        Commands::Verify(args) => {
            tracing::info!(from_seq = ?args.from_seq, "Verifying SQLite ledger chain");
            verify_cmd::execute(args, cli.json, &config.storage.ledger_path)?;
            Ok(())
        }
        Commands::Receipt(args) => {
            let db_path = args
                .db_path
                .as_deref()
                .unwrap_or(&config.storage.ledger_path)
                .to_path_buf();
            receipt_cmd::execute(args, cli.json, &db_path)?;
            Ok(())
        }
        Commands::Doctor => {
            doctor::run_doctor(&config)?;
            Ok(())
        }
    }
}
