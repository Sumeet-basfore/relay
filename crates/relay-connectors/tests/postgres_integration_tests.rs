//! End-to-end PostgreSQL connector integration tests using Testcontainers.

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::postgres::{PostgresClient, PostgresClientConfig, PostgresConnector};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{CredentialProviderType, PolicyEngine, PrincipalId};
use relay_ledger::SqliteLedger;
use relay_policy::CedarPolicyEngine;
use relay_receipts::{Ed25519ReceiptSigner, ReceiptVerifier};
use std::sync::Arc;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const TEST_PG_USER: &str = "postgres";
const TEST_PG_PASSWORD: &str = "postgres";

const EXTENDED_POLICY: &str = r#"
@id("permit_postgres_writes")
permit (
    principal,
    action in [Relay::Action::"postgres.write"],
    resource
);
"#;

async fn setup_postgres_pipeline(
    host: &str,
    port: u16,
    database: &str,
    extended_policy: bool,
) -> (
    ActionCanonicalizer,
    Arc<CedarPolicyEngine>,
    Arc<JitCredentialBroker>,
    PostgresConnector,
    Ed25519ReceiptSigner,
) {
    let canonicalizer = ActionCanonicalizer::default();

    let policy_engine = if extended_policy {
        let policy_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/default.cedar");
        let default = std::fs::read_to_string(policy_path).expect("default policy");
        Arc::new(CedarPolicyEngine::from_str(&format!("{default}\n{EXTENDED_POLICY}"), None).unwrap())
    } else {
        Arc::new(CedarPolicyEngine::default_engine().unwrap())
    };

    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret(
            "postgres_password",
            format!("{TEST_PG_USER}:{TEST_PG_PASSWORD}").into_bytes(),
        )
        .await;
    broker.register_provider(provider).await;

    let mut client_config = PostgresClientConfig::loopback_test();
    client_config.default_port = port;
    let client = Arc::new(PostgresClient::new(client_config).expect("postgres client"));
    let connector = PostgresConnector::new(client, "postgres_password");
    let signer = Ed25519ReceiptSigner::generate("relay-test-postgres-v1");

    // Seed schema via direct connection for deterministic tests.
    seed_test_schema(host, port, database).await;

    (
        canonicalizer,
        policy_engine,
        broker,
        connector,
        signer,
    )
}

async fn seed_test_schema(host: &str, port: u16, database: &str) {
    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={host} port={port} user={TEST_PG_USER} password={TEST_PG_PASSWORD} dbname={database}"
        ),
        tokio_postgres::NoTls,
    )
    .await
    .expect("seed connection");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS metrics (id serial PRIMARY KEY, name text NOT NULL, value int NOT NULL);\n            TRUNCATE metrics;\n            INSERT INTO metrics (name, value) VALUES ('alpha', 1), ('beta', 2);",
        )
        .await
        .expect("seed schema");
}

#[tokio::test]
async fn test_postgres_select_allowed_full_pipeline() {
    let container = Postgres::default().start()
        .await
        .expect("postgres container");

    let host = "127.0.0.1";
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let database = "postgres";

    let (canonicalizer, policy_engine, broker, connector, signer) =
        setup_postgres_pipeline(host, port, database, false).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", "read");
    let args = serde_json::json!({
        "host": host,
        "database": database,
        "query": "SELECT name, value FROM metrics ORDER BY id"
    });

    let canonical_action = canonicalizer
        .canonicalize(
            session_id,
            principal,
            "tools/call",
            tool_ident,
            &args,
            None,
            None,
        )
        .unwrap();

    let auth_req = canonical_action.to_authorization_request().unwrap();
    let decision = policy_engine.evaluate(&auth_req).await.unwrap();
    assert!(decision.is_allowed());

    let (result, receipt) = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &*broker, &signer)
        .await
        .expect("select execution");

    assert_eq!(result.exit_code, 0);
    assert!(!result.is_error);

    let verifier = ReceiptVerifier::new(signer.verifying_key());
    assert!(verifier
        .verify_receipt(&receipt, Some(&canonical_action.action_hash), Some(&decision.policy_digest))
        .is_valid());

    use relay_domain::Ledger;
    let ledger = SqliteLedger::in_memory().unwrap();
    ledger.append(&receipt).await.unwrap();
    assert!(ledger.verify_chain().await.unwrap());
}

#[tokio::test]
async fn test_postgres_update_allowed_with_extended_policy() {
    let container = Postgres::default().start()
        .await
        .expect("postgres container");

    let host = "127.0.0.1";
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let database = "postgres";

    let (canonicalizer, policy_engine, broker, connector, _) =
        setup_postgres_pipeline(host, port, database, true).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", "write");
    let args = serde_json::json!({
        "host": host,
        "database": database,
        "query": "UPDATE metrics SET value = 99 WHERE name = 'alpha'"
    });

    let canonical_action = canonicalizer
        .canonicalize(session_id, principal, "tools/call", tool_ident, &args, None, None)
        .unwrap();

    let decision = policy_engine
        .evaluate(&canonical_action.to_authorization_request().unwrap())
        .await
        .unwrap();
    assert!(decision.is_allowed());

    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await
        .expect("update allowed");
    assert_eq!(result.exit_code, 0);
}

#[tokio::test]
async fn test_postgres_delete_denied_by_policy() {
    let container = Postgres::default().start()
        .await
        .expect("postgres container");

    let host = "127.0.0.1";
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let database = "postgres";

    let (canonicalizer, policy_engine, broker, connector, _) =
        setup_postgres_pipeline(host, port, database, false).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", "write");
    let args = serde_json::json!({
        "host": host,
        "database": database,
        "query": "DELETE FROM metrics WHERE name = 'alpha'"
    });

    let canonical_action = canonicalizer
        .canonicalize(session_id, principal, "tools/call", tool_ident, &args, None, None)
        .unwrap();

    let decision = policy_engine
        .evaluate(&canonical_action.to_authorization_request().unwrap())
        .await
        .unwrap();

    assert!(decision.is_denied());

    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_postgres_ddl_denied_by_policy() {
    let container = Postgres::default().start()
        .await
        .expect("postgres container");

    let host = "127.0.0.1";
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let database = "postgres";

    let (canonicalizer, policy_engine, broker, connector, _) =
        setup_postgres_pipeline(host, port, database, false).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", "ddl");
    let args = serde_json::json!({
        "host": host,
        "database": database,
        "query": "DROP TABLE metrics"
    });

    let canonical_action = canonicalizer
        .canonicalize(session_id, principal, "tools/call", tool_ident, &args, None, None)
        .unwrap();

    let decision = policy_engine
        .evaluate(&canonical_action.to_authorization_request().unwrap())
        .await
        .unwrap();
    assert!(decision.is_denied());

    let result = connector
        .execute_governed(&canonical_action, &decision, &*broker)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_postgres_action_hash_mismatch_blocks_execution() {
    let container = Postgres::default().start()
        .await
        .expect("postgres container");

    let host = "127.0.0.1";
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let database = "postgres";

    let (canonicalizer, policy_engine, broker, connector, _) =
        setup_postgres_pipeline(host, port, database, false).await;

    let session_id = relay_domain::SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool_ident = ToolIdentity::new("relay", "postgres", "read");
    let args = serde_json::json!({
        "host": host,
        "database": database,
        "query": "SELECT name FROM metrics"
    });

    let canonical_action = canonicalizer
        .canonicalize(session_id, principal, "tools/call", tool_ident, &args, None, None)
        .unwrap();

    let decision = policy_engine
        .evaluate(&canonical_action.to_authorization_request().unwrap())
        .await
        .unwrap();

    let mut bad_decision = decision.clone();
    bad_decision.action_hash = relay_domain::ActionHash::compute(b"tampered");

    let result = connector
        .execute_governed(&canonical_action, &bad_decision, &*broker)
        .await;
    assert!(result.is_err());
}
