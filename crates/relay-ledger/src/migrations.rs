//! SQLite schema migrations engine for Relay Ledger.
//!
//! Complies with A006 §8: Pure forward migrations with SHA-256 integrity verification.

use chrono::Utc;
use relay_domain::LedgerError;
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};

const V001_SQL: &str = include_str!("schema.sql");

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "001_initial_schema",
    sql: V001_SQL,
}];

/// Computes the hex SHA-256 checksum of a migration SQL string
fn compute_checksum(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    hex::encode(hasher.finalize())
}

/// Runs all pending forward migrations inside an immediate transaction.
pub fn apply_migrations(conn: &mut Connection) -> Result<(), LedgerError> {
    // 1. Begin immediate transaction for migrations
    conn.execute_batch("BEGIN IMMEDIATE;").map_err(|e| {
        LedgerError::ConnectionFailed(format!("Failed to begin migration transaction: {e}"))
    })?;

    // 2. Ensure schema_migrations table exists
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version         INTEGER PRIMARY KEY,
            name            TEXT NOT NULL,
            applied_at_utc  TEXT NOT NULL,
            checksum_sha256 TEXT NOT NULL
        );",
    )
    .map_err(|e| {
        LedgerError::MigrationFailed(format!("Failed to create schema_migrations table: {e}"))
    })?;

    // 3. Query already applied migrations
    let mut applied = std::collections::BTreeMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT version, checksum_sha256 FROM schema_migrations ORDER BY version ASC")
            .map_err(|e| {
                LedgerError::QueryError(format!("Failed to query schema_migrations: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                let v: u32 = row.get(0)?;
                let c: String = row.get(1)?;
                Ok((v, c))
            })
            .map_err(|e| {
                LedgerError::QueryError(format!("Failed to map schema_migrations: {e}"))
            })?;

        for item in rows {
            let (v, c) = item.map_err(|e| LedgerError::QueryError(e.to_string()))?;
            applied.insert(v, c);
        }
    }

    // 4. Verify historical integrity of applied migrations
    for m in MIGRATIONS {
        let expected_checksum = compute_checksum(m.sql);
        if let Some(recorded_checksum) = applied.get(&m.version) {
            if recorded_checksum != &expected_checksum {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(LedgerError::Corruption(format!(
                    "Migration v{} ({}) checksum mismatch: recorded '{}', expected '{}'",
                    m.version, m.name, recorded_checksum, expected_checksum
                )));
            }
        }
    }

    // 5. Apply new migrations sequentially
    for m in MIGRATIONS {
        if applied.contains_key(&m.version) {
            continue;
        }

        tracing::info!(
            version = m.version,
            name = m.name,
            "Applying SQLite schema migration"
        );

        // Execute migration batch
        conn.execute_batch(m.sql).map_err(|e| {
            let _ = conn.execute_batch("ROLLBACK;");
            LedgerError::MigrationFailed(format!("Migration v{} failed: {e}", m.version))
        })?;

        // Record migration record
        let checksum = compute_checksum(m.sql);
        let now_utc = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at_utc, checksum_sha256)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![m.version, m.name, now_utc, checksum],
        )
        .map_err(|e| {
            let _ = conn.execute_batch("ROLLBACK;");
            LedgerError::MigrationFailed(format!("Failed to record migration v{}: {e}", m.version))
        })?;
    }

    // 6. Commit migration transaction
    conn.execute_batch("COMMIT;").map_err(|e| {
        LedgerError::WriteError(format!("Failed to commit migration transaction: {e}"))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_migrations_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();

        // Run again; must succeed idempotently
        apply_migrations(&mut conn).unwrap();

        // Check tables exist
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('ledger_entries', 'receipts', 'schema_migrations', 'node_identity')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_checksum_tamper_detection() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();

        // Tamper with checksum in schema_migrations
        conn.execute(
            "UPDATE schema_migrations SET checksum_sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE version = 1",
            [],
        )
        .unwrap();

        // Re-applying migrations must detect corruption
        let res = apply_migrations(&mut conn);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("checksum mismatch"));
    }
}
