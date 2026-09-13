//! Unit tests for PostgreSQL connector classification, binding, and scope enforcement.

use relay_canonical::{SqlNormalizer, SqlOperation};
use relay_connectors::postgres::{
    PostgresClientConfig, PostgresCredentials, PostgresResource, validate_supported_surface,
};
use relay_connectors::postgres::scope::{
    is_mutating_operation, validate_operation_class, validate_table_scope,
};

#[test]
fn test_sql_operation_classification() {
    let select = SqlNormalizer::normalize("SELECT id FROM users").unwrap();
    assert_eq!(select.operation, SqlOperation::Select);

    let insert = SqlNormalizer::normalize("INSERT INTO users (id) VALUES (1)").unwrap();
    assert_eq!(insert.operation, SqlOperation::Insert);

    let update = SqlNormalizer::normalize("UPDATE users SET active = true WHERE id = 1").unwrap();
    assert_eq!(update.operation, SqlOperation::Update);

    let delete = SqlNormalizer::normalize("DELETE FROM users WHERE id = 1").unwrap();
    assert_eq!(delete.operation, SqlOperation::Delete);

    let ddl = SqlNormalizer::normalize("CREATE TABLE audit (id int)").unwrap();
    assert_eq!(ddl.operation, SqlOperation::Ddl);
}

#[test]
fn test_unsupported_construct_rejection() {
    assert!(SqlNormalizer::normalize("COPY users TO '/tmp/x'").is_err());
    assert!(validate_supported_surface("SELECT 1; DROP TABLE users").is_err());
    assert!(validate_supported_surface("DO $$ BEGIN PERFORM 1; END $$").is_err());
    assert!(validate_supported_surface("CALL my_proc()").is_err());
}

#[test]
fn test_resource_binding_parsing() {
    let res = PostgresResource::parse("postgres://localhost/relaydb/public.users").unwrap();
    assert_eq!(res.host, "localhost");
    assert_eq!(res.database, "relaydb");
    assert_eq!(res.tables, vec!["public.users".to_string()]);
}

#[test]
fn test_resource_scope_validation() {
    let resource = PostgresResource::parse("postgres://localhost/db/public.users").unwrap();
    let norm = SqlNormalizer::normalize("SELECT * FROM public.users").unwrap();
    assert!(validate_table_scope(&resource, &norm, "public").is_ok());

    let cross = SqlNormalizer::normalize("SELECT * FROM public.orders").unwrap();
    assert!(validate_table_scope(&resource, &cross, "public").is_err());
}

#[test]
fn test_operation_class_validation() {
    assert!(validate_operation_class("read", SqlOperation::Select).is_ok());
    assert!(validate_operation_class("query", SqlOperation::Select).is_ok());
    assert!(validate_operation_class("write", SqlOperation::Update).is_ok());
    assert!(validate_operation_class("read", SqlOperation::Delete).is_err());
}

#[test]
fn test_multi_statement_rejection() {
    let err = SqlNormalizer::normalize("SELECT 1; DROP TABLE users").unwrap_err();
    assert!(err.to_string().contains("Multi-statement"));
}

#[test]
fn test_credential_parsing_json_and_delimited() {
    let json = br#"{"username":"relay","password":"secret"}"#;
    let creds = PostgresCredentials::from_secret_bytes(json).unwrap();
    assert_eq!(creds.username, "relay");
    assert_eq!(creds.password, "secret");

    let delim = b"relay:secret";
    let creds2 = PostgresCredentials::from_secret_bytes(delim).unwrap();
    assert_eq!(creds2.username, "relay");
}

#[test]
fn test_host_validation_rejects_injection() {
    let cfg = PostgresClientConfig::default();
    assert!(cfg.validate_host("evil.com?sslmode=disable").is_err());
    assert!(cfg.validate_host("user@host").is_err());
}

#[test]
fn test_mutating_operation_classification() {
    assert!(!is_mutating_operation(SqlOperation::Select));
    assert!(is_mutating_operation(SqlOperation::Update));
    assert!(is_mutating_operation(SqlOperation::Ddl));
}
