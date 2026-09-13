mod common;

use common::*;
use relay_domain::Ledger;
use relay_ledger::{SqliteLedger, SqliteStorageEngine};
use tempfile::tempdir;

#[tokio::test]
async fn test_file_durability_and_wal_reopen() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("ledger.db");

    let signer = create_test_signer();
    let pubkey_hex = hex::encode(signer.export_public_key());

    let genesis_hash;
    let entry1_hash;

    // First session: open, initialize genesis, append 2 receipts
    {
        let ledger = SqliteLedger::open(&db_path).unwrap();
        let genesis = ledger
            .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
            .await
            .unwrap();
        genesis_hash = genesis.entry_hash;

        let receipt1 = build_signed_test_receipt(&signer, "action_1", genesis_hash);
        let entry1 = ledger.append(&receipt1).await.unwrap();
        entry1_hash = entry1.entry_hash;

        let receipt2 = build_signed_test_receipt(&signer, "action_2", entry1_hash);
        let _entry2 = ledger.append(&receipt2).await.unwrap();

        assert_eq!(ledger.count().await.unwrap(), 3);
        // Dropping ledger here simulates daemon shutdown
    }

    // Verify pragmas on disk
    {
        let engine = SqliteStorageEngine::open(&db_path).unwrap();
        let conn = engine.raw_connection();

        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_lowercase(), "wal");

        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
    }

    // Second session: re-open from same file
    {
        let ledger = SqliteLedger::open(&db_path).unwrap();

        // Must still have 3 entries
        assert_eq!(ledger.count().await.unwrap(), 3);

        // Verification of existing chain must pass
        let report = ledger.verify(None).await.unwrap();
        assert!(report.status.is_valid());
        assert_eq!(report.total_verified_entries, 3);
        assert_eq!(report.head_sequence, 2);

        // Append 3rd receipt continuing the existing chain
        let latest_hash = ledger.get_latest_entry_hash().await.unwrap();
        let receipt3 = build_signed_test_receipt(&signer, "action_3", latest_hash);
        let entry3 = ledger.append(&receipt3).await.unwrap();

        assert_eq!(entry3.sequence_number.as_u64(), 3);
        assert_eq!(ledger.count().await.unwrap(), 4);

        // Verify entire chain survives and extends cleanly
        let report_after = ledger.verify(None).await.unwrap();
        assert!(report_after.status.is_valid());
        assert_eq!(report_after.total_verified_entries, 4);
        assert_eq!(report_after.head_sequence, 3);
    }
}
