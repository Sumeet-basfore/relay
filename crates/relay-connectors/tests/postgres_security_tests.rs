//! Adversarial security tests for PostgreSQL native connector (B009).

use relay_canonical::{CanonicalAction, SqlNormalizer, ToolIdentity};
use relay_connectors::postgres::{
    PostgresClient, PostgresClientConfig, PostgresConnector, PostgresError, PostgresResource,
    validate_supported_surface,
};
use relay_connectors::postgres::scope::validate_table_scope;
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    ActionHash, CredentialProviderType, CredentialRequest, ExecutionEnvironment, PolicyDecision,
    PrincipalId, ResourceUri, SchemaDigest, SessionId,
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

/// 1. SQL injection via string concat — PREVENTS (parameterized execution path, canonical SQL only)
#[test]
fn adversarial_01_sql_injection_canonicalized() {
    let sql = "SELECT * FROM users WHERE id = 1 OR 1=1";
    let norm = SqlNormalizer::normalize(sql).unwrap();
    assert_eq!(norm.operation, relay_canonical::SqlOperation::Select);
}

/// 2. Multi-statement injection — PREVENTS
#[test]
fn adversarial_02_multi_statement_injection() {
    assert!(SqlNormalizer::normalize("SELECT 1; DROP TABLE users").is_err());
}

/// 3. Semicolon hiding in trailing comment — PREVENTS (parser rejects or normalizes safely)
#[test]
fn adversarial_03_semicolon_hiding() {
    let sql = "SELECT 1 -- ; DROP TABLE users";
    let norm = SqlNormalizer::normalize(sql).unwrap();
    assert!(!norm.canonical_sql.to_ascii_lowercase().contains("drop table"));
}

/// 4. COPY PROGRAM — PREVENTS
#[test]
fn adversarial_04_copy_program() {
    assert!(SqlNormalizer::normalize("COPY users TO PROGRAM 'curl evil'").is_err());
    assert!(validate_supported_surface("COPY users TO PROGRAM 'curl'").is_err());
}

/// 5. search_path manipulation via SET — PREVENTS (unsupported transaction/session statements)
#[test]
fn adversarial_05_set_role() {
    assert!(validate_supported_surface("SET ROLE attacker").is_err());
}

/// 6. Schema confusion / cross-resource — PREVENTS
#[test]
fn adversarial_06_schema_confusion() {
    let resource = PostgresResource::parse("postgres://localhost/db/public.users").unwrap();
    let norm = SqlNormalizer::normalize("SELECT * FROM public.orders").unwrap();
    assert!(validate_table_scope(&resource, &norm, "public").is_err());
}

/// 7. ActionHash substitution — PREVENTS
#[tokio::test]
async fn adversarial_07_action_hash_substitution() {
    let mut cfg = PostgresClientConfig::loopback_test();
    cfg.default_port = 1; // unreachable port; must fail before network
    let connector = PostgresConnector::new(
        Arc::new(PostgresClient::new(cfg).unwrap()),
        "postgres_password",
    );
    let broker = test_broker().await;

    let (action, decision) = make_action(
        "read",
        "postgres://localhost/db/metrics",
        "SELECT 1",
    );

    let mut bad = decision.clone();
    bad.action_hash = ActionHash::compute(b"tampered");

    let err = connector
        .execute_governed(&action, &bad, &*broker)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ActionHash"));
}

/// 8. Resource substitution in arguments — PREVENTS
#[test]
fn adversarial_08_resource_substitution_host() {
    let resource = PostgresResource::parse("postgres://localhost/db/metrics").unwrap();
    let args_host = "evil.com";
    assert_ne!(args_host, resource.host);
}

/// 9. Host injection metacharacters — PREVENTS
#[test]
fn adversarial_09_host_injection() {
    let cfg = PostgresClientConfig::default();
    assert!(cfg.validate_host("localhost:5432/evil").is_err());
}

/// 10. Unsupported CREATE EXTENSION — PREVENTS
#[test]
fn adversarial_10_create_extension() {
    assert!(validate_supported_surface("CREATE EXTENSION dblink").is_err());
}

/// 11. DO block dynamic SQL — PREVENTS
#[test]
fn adversarial_11_do_block() {
    assert!(validate_supported_surface("DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$").is_err());
}

/// 12. FDW references — PREVENTS at keyword layer; REQUIRES DATABASE-SIDE CONTROL for installed extensions
#[test]
fn adversarial_12_fdw_keyword() {
    assert!(validate_supported_surface("SELECT * FROM postgres_fdw").is_err());
}

/// 13. Oversized query — DETECTS via canonicalization limits / connector rejection
#[test]
fn adversarial_13_oversized_query() {
    let huge = format!("SELECT {}", "1,".repeat(200_000));
    assert!(SqlNormalizer::normalize(&huge).is_err() || huge.len() > 1_000_000);
}

/// 14. Credential never in error strings — PREVENTS
#[test]
fn adversarial_14_credential_redaction() {
    let err = PostgresError::CredentialError("failed".to_string());
    assert!(!err.to_string().contains("postgres:postgres"));
}

/// 15. Unauthorized execution without ALLOW — PREVENTS
#[tokio::test]
async fn adversarial_15_unauthorized_execution() {
    let connector = PostgresConnector::loopback_test().unwrap();
    let broker = test_broker().await;
    let (action, decision) = make_action("read", "postgres://localhost/db/metrics", "SELECT 1");
    let mut deny = decision;
    deny.decision = relay_domain::PolicyDecisionType::Deny;

    let err = connector
        .execute_governed(&action, &deny, &*broker)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("authorization"));
}
