use clap::Parser;

mod cli;
mod cli_error;
mod config;
mod doctor;
mod logging;
mod receipt_cmd;
mod run;
mod verify_cmd;

use cli::{Cli, Commands, PolicySubcommands, SecretSubcommands};
use cli_error::CliError;
use config::RelayConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize structured logging strictly directed to stderr
    logging::init_logging(cli.verbose, cli.quiet, cli.json);

    // Load configuration
    let _config = RelayConfig::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Run(args) => {
            run::execute(args).await?;
            Ok(())
        }
        Commands::Policy(args) => match args.command {
            PolicySubcommands::Validate { path } => {
                tracing::info!(path = ?path, "Validating Cedar policies");
                Err(CliError::NotImplemented(
                    "relay policy validate is scheduled for milestone B004".to_string(),
                )
                .into())
            }
            PolicySubcommands::Test { fixtures } => {
                tracing::info!(fixtures = ?fixtures, "Testing Cedar policies");
                Err(CliError::NotImplemented(
                    "relay policy test is scheduled for milestone B004".to_string(),
                )
                .into())
            }
        },
        Commands::Secret(args) => match args.command {
            SecretSubcommands::Set { key, .. } => {
                tracing::info!(key = %key, "Setting secret in keyring");
                Err(CliError::NotImplemented(
                    "relay secret set is scheduled for milestone B005".to_string(),
                )
                .into())
            }
            SecretSubcommands::Get { key } => {
                tracing::info!(key = %key, "Querying secret in keyring");
                Err(CliError::NotImplemented(
                    "relay secret get is scheduled for milestone B005".to_string(),
                )
                .into())
            }
            SecretSubcommands::List => {
                tracing::info!("Listing secrets in keyring");
                Err(CliError::NotImplemented(
                    "relay secret list is scheduled for milestone B005".to_string(),
                )
                .into())
            }
            SecretSubcommands::Delete { key } => {
                tracing::info!(key = %key, "Deleting secret from keyring");
                Err(CliError::NotImplemented(
                    "relay secret delete is scheduled for milestone B005".to_string(),
                )
                .into())
            }
        },
        Commands::Verify(args) => {
            tracing::info!(from_seq = ?args.from_seq, "Verifying SQLite ledger chain");
            verify_cmd::execute(args, cli.json, &_config.storage.ledger_path)?;
            Ok(())
        }
        Commands::Receipt(args) => {
            let db_path = args
                .db_path
                .as_deref()
                .unwrap_or(&_config.storage.ledger_path)
                .to_path_buf();
            receipt_cmd::execute(args, cli.json, &db_path)?;
            Ok(())
        }
        Commands::Doctor => {
            doctor::run_doctor()?;
            Ok(())
        }
    }
}
