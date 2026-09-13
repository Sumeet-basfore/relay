//! Handler for `relay receipt` CLI queries.

use relay_domain::ReceiptId;
use relay_ledger::SqliteStorageEngine;
use std::path::Path;

use crate::cli::{ReceiptArgs, ReceiptSubcommands};
use crate::cli_error::CliError;

/// Executes the receipt query subcommands
pub fn execute(args: ReceiptArgs, json_mode: bool, db_path: &Path) -> Result<(), CliError> {
    if !db_path.exists() {
        return Err(CliError::StorageError(format!(
            "Ledger database not found at '{}'",
            db_path.display()
        )));
    }

    let engine =
        SqliteStorageEngine::open(db_path).map_err(|e| CliError::StorageError(e.to_string()))?;

    match args.command {
        ReceiptSubcommands::Get { id } => {
            let receipt_id = id
                .parse::<ReceiptId>()
                .map_err(|e| CliError::StorageError(format!("Invalid Receipt ID '{id}': {e}")))?;

            let receipt = engine
                .get_receipt_by_id(&receipt_id)
                .map_err(|e| CliError::StorageError(e.to_string()))?;

            match receipt {
                Some(r) => {
                    if json_mode {
                        let json = serde_json::to_string_pretty(&r)
                            .map_err(|e| CliError::InternalError(e.to_string()))?;
                        println!("{json}");
                    } else {
                        println!("==================================================");
                        println!("   Action Receipt: {}", r.receipt_id);
                        println!("==================================================");
                        println!("Created At:       {}", r.created_at.to_rfc3339());
                        println!("Action ID:        {}", r.action_id);
                        println!("Session ID:       {}", r.session_id);
                        println!("Action Hash:      {}", r.action_hash.to_hex());
                        println!("Receipt Hash:     {}", r.receipt_hash.to_hex());
                        println!("Parent Hash:      {}", r.parent_receipt_hash.to_hex());
                        println!("DSSE Signatures:  {}", r.dsse_envelope.signatures.len());
                        for (i, sig) in r.dsse_envelope.signatures.iter().enumerate() {
                            println!("  Sig #{}: keyid='{}'", i + 1, sig.keyid);
                        }
                        println!("==================================================");
                    }
                    Ok(())
                }
                None => Err(CliError::StorageError(format!(
                    "Receipt '{id}' not found in ledger"
                ))),
            }
        }
        ReceiptSubcommands::List { limit } => {
            let entries = engine
                .list_recent(limit)
                .map_err(|e| CliError::StorageError(e.to_string()))?;

            if json_mode {
                let json = serde_json::to_string_pretty(&entries)
                    .map_err(|e| CliError::InternalError(e.to_string()))?;
                println!("{json}");
            } else {
                println!("================================================================================");
                println!("SEQ   TIMESTAMP (UTC)       RECEIPT ID                             PAYLOAD HASH");
                println!("================================================================================");
                for entry in entries {
                    let ts_short = entry.recorded_at.format("%Y-%m-%d %H:%M:%S");
                    let hash_prefix = if entry.receipt_hash.to_hex().len() >= 16 {
                        &entry.receipt_hash.to_hex()[..16]
                    } else {
                        ""
                    };
                    println!(
                        "#{:<4} {:<19}  {:<36}  {}...",
                        entry.sequence_number.as_u64(),
                        ts_short,
                        entry.receipt_id,
                        hash_prefix
                    );
                }
                println!("================================================================================");
            }
            Ok(())
        }
    }
}
