//! Performance characterization for PostgreSQL connector local overhead.

use relay_canonical::{ActionCanonicalizer, SqlNormalizer, ToolIdentity};
use relay_connectors::postgres::{validate_supported_surface, PostgresClientConfig};
use relay_domain::PrincipalId;
use std::time::Instant;

#[test]
fn test_postgres_local_overhead_characterization() {
    let sql = "SELECT id, name, value FROM metrics WHERE active = true";
    let iterations = 1_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let norm = SqlNormalizer::normalize(sql).unwrap();
        validate_supported_surface(&norm.canonical_sql).unwrap();
    }
    let normalize_ms = start.elapsed().as_millis();

    let canonicalizer = ActionCanonicalizer::default();
    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", "read");
    let args = serde_json::json!({
        "host": "localhost",
        "database": "db",
        "query": sql
    });

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = canonicalizer
            .canonicalize(
                session_id,
                principal.clone(),
                "tools/call",
                tool_ident.clone(),
                &args,
                None,
                None,
            )
            .unwrap();
    }
    let canonicalize_ms = start.elapsed().as_millis();

    // Local overhead targets (excluding remote PostgreSQL latency)
    assert!(
        normalize_ms < 5_000,
        "SQL normalization too slow: {normalize_ms}ms"
    );
    assert!(
        canonicalize_ms < 10_000,
        "Canonicalization too slow: {canonicalize_ms}ms"
    );

    let _cfg = PostgresClientConfig::default();
}
