//! Handler for `relay verify` and `relay verify-ledger` CLI commands.
//!
//! Complies with A006 §7: Systematic Offline Ledger Verification.

use relay_ledger::{LedgerVerificationReport, LedgerVerificationStatus, LedgerVerifier};
use std::path::Path;

use crate::cli::VerifyArgs;
use crate::cli_error::CliError;

/// Executes the ledger verification command
pub fn execute(args: VerifyArgs, json_mode: bool, default_db_path: &Path) -> Result<(), CliError> {
    let db_path = args.db_path.as_deref().unwrap_or(default_db_path);

    if !db_path.exists() {
        return Err(CliError::StorageError(format!(
            "Ledger database file not found at '{}'",
            db_path.display()
        )));
    }

    // Load optional public key bytes
    let pubkey_bytes: Option<[u8; 32]> = if let Some(ref p) = args.pubkey_path {
        let content = std::fs::read(p).map_err(|e| {
            CliError::StorageError(format!("Failed to read pubkey file '{}': {e}", p.display()))
        })?;
        if content.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&content);
            Some(arr)
        } else if let Ok(s) = std::str::from_utf8(&content) {
            let trimmed = s.trim();
            if let Ok(hex_bytes) = hex::decode(trimmed) {
                if hex_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&hex_bytes);
                    Some(arr)
                } else {
                    return Err(CliError::StorageError(
                        "Public key hex string must decode to 32 bytes".to_string(),
                    ));
                }
            } else {
                return Err(CliError::StorageError(
                    "Unrecognized public key file format (must be 32 raw bytes or 64 hex chars)"
                        .to_string(),
                ));
            }
        } else {
            return Err(CliError::StorageError(
                "Invalid public key file size (must be 32 bytes)".to_string(),
            ));
        }
    } else {
        None
    };

    let report: LedgerVerificationReport =
        LedgerVerifier::verify_file(db_path, pubkey_bytes.as_ref(), args.from_seq)
            .map_err(|e| CliError::StorageError(e.to_string()))?;

    if json_mode {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| CliError::InternalError(e.to_string()))?;
        println!("{json}");
    } else {
        println!("==================================================");
        println!("   Relay Cryptographic Ledger Verification");
        println!("==================================================");
        println!("Ledger Database:  {}", db_path.display());
        println!("Verified At:      {}", report.verified_at.to_rfc3339());
        println!("Verification Time: {} ms", report.duration_ms);
        println!("Total Entries:    {}", report.total_verified_entries);

        if report.total_verified_entries > 0 {
            println!("Head Sequence:    #{}", report.head_sequence);
            println!("Genesis Hash:     {}", report.genesis_hash);
            println!("Head Entry Hash:  {}", report.head_hash);
        }

        match &report.status {
            LedgerVerificationStatus::Valid => {
                println!("Status:           ✓ VALID (Hash chain and signatures verified)");
            }
            LedgerVerificationStatus::EmptyLedger => {
                println!("Status:           ! EMPTY (No entries in ledger)");
            }
            LedgerVerificationStatus::SequenceGap { expected, actual } => {
                println!("Status:           ✗ FAILED: Sequence gap detected");
                println!("Details:          Expected sequence #{expected}, found #{actual}");
            }
            LedgerVerificationStatus::BrokenChain {
                sequence_number,
                expected_parent,
                actual_parent,
            } => {
                println!("Status:           ✗ FAILED: Cryptographic hash chain broken");
                println!("Sequence:         #{sequence_number}");
                println!("Expected Parent:  {expected_parent}");
                println!("Recorded Parent:  {actual_parent}");
            }
            LedgerVerificationStatus::PayloadHashMismatch {
                sequence_number,
                expected,
                computed,
            } => {
                println!("Status:           ✗ FAILED: Payload hash mismatch (tampered DSSE)");
                println!("Sequence:         #{sequence_number}");
                println!("Expected Hash:    {expected}");
                println!("Computed Hash:    {computed}");
            }
            LedgerVerificationStatus::EntryHashMismatch {
                sequence_number,
                expected,
                computed,
            } => {
                println!("Status:           ✗ FAILED: Entry hash formula mismatch");
                println!("Sequence:         #{sequence_number}");
                println!("Expected Hash:    {expected}");
                println!("Computed Hash:    {computed}");
            }
            LedgerVerificationStatus::InvalidSignature {
                sequence_number,
                receipt_id,
                reason,
            } => {
                println!("Status:           ✗ FAILED: Digital signature invalid");
                println!("Sequence:         #{sequence_number}");
                println!("Receipt ID:       {receipt_id}");
                println!("Reason:           {reason}");
            }
            LedgerVerificationStatus::CorruptedDatabase(err) => {
                println!("Status:           ✗ FAILED: Database corruption detected");
                println!("Details:          {err}");
            }
        }
        println!("==================================================");
    }

    if !report.status.is_valid() {
        return Err(CliError::StorageError(format!(
            "Ledger verification failed: {:?}",
            report.status
        )));
    }

    Ok(())
}
