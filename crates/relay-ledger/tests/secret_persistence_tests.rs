mod common;

use common::*;
use relay_domain::Ledger;
use relay_ledger::SqliteLedger;
use tempfile::tempdir;

#[tokio::test]
async fn test_zero_secrets_persisted_in_sqlite_database() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("secure_audit_ledger.db");

    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let ledger = SqliteLedger::open(&db_path).unwrap();
    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    // Append 5 receipts
    let mut prev_hash = genesis.entry_hash;
    for i in 1..=5 {
        let receipt = build_signed_test_receipt(&signer, &format!("action_{i}"), prev_hash);
        let entry = ledger.append(&receipt).await.unwrap();
        prev_hash = entry.entry_hash;
    }

    // Force WAL checkpoint so data is flushed to main database file
    {
        let engine = relay_ledger::SqliteStorageEngine::open(&db_path).unwrap();
        engine
            .raw_connection()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // Prohibited secret signatures that must NEVER appear in SQLite
    let prohibited_patterns = [
        "ghp_",
        "gho_",
        "github_pat_",
        "Bearer ",
        "sk_live_",
        "AKIA",
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "password",
        "client_secret",
    ];

    // 1. Audit raw file bytes
    let raw_db_bytes = std::fs::read(&db_path).expect("Failed to read database file");
    let raw_db_str = String::from_utf8_lossy(&raw_db_bytes);

    for pattern in prohibited_patterns {
        assert!(
            !raw_db_str.contains(pattern),
            "Security Invariant SI-007 Violation: raw DB file contains prohibited pattern '{pattern}'"
        );
    }

    // Check WAL file if present
    let wal_path = dir.path().join("secure_audit_ledger.db-wal");
    if wal_path.exists() {
        let raw_wal_bytes = std::fs::read(&wal_path).expect("Failed to read WAL file");
        let raw_wal_str = String::from_utf8_lossy(&raw_wal_bytes);
        for pattern in prohibited_patterns {
            assert!(
                !raw_wal_str.contains(pattern),
                "Security Invariant SI-007 Violation: WAL file contains prohibited pattern '{pattern}'"
            );
        }
    }

    // 2. Audit all SQLite tables and columns via SQL queries
    let engine = relay_ledger::SqliteStorageEngine::open(&db_path).unwrap();
    let conn = engine.raw_connection();

    let mut stmt = conn
        .prepare("SELECT tool_namespace, tool_name, decision, status, dsse_envelope FROM receipts")
        .unwrap();

    let rows = stmt
        .query_map([], |row| {
            let ns: String = row.get(0)?;
            let tname: String = row.get(1)?;
            let dec: String = row.get(2)?;
            let st: String = row.get(3)?;
            let envelope: Vec<u8> = row.get(4)?;
            Ok((ns, tname, dec, st, envelope))
        })
        .unwrap();

    for row in rows {
        let (ns, tname, dec, st, envelope) = row.unwrap();
        let env_str = String::from_utf8_lossy(&envelope);

        for pattern in prohibited_patterns {
            assert!(!ns.contains(pattern), "Found secret pattern in namespace");
            assert!(
                !tname.contains(pattern),
                "Found secret pattern in tool_name"
            );
            assert!(!dec.contains(pattern), "Found secret pattern in decision");
            assert!(!st.contains(pattern), "Found secret pattern in status");
            assert!(
                !env_str.contains(pattern),
                "Found secret pattern in dsse_envelope"
            );
        }
    }
}
