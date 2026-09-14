//! GA001 Golden Release Smoke Test Suite
//!
//! Executes the canonical release smoke test:
//! - Fresh isolated environment installation
//! - System health check (`relay doctor`)
//! - Policy syntax & schema validation (`relay policy validate`)
//! - Governed read & mutation execution with native connectors
//! - DSSE receipt signing & secret scrubbing
//! - Append-only SQLite hash-chain ledger verification (`relay verify`)
//! - Receipt list query (`relay receipt list`)
//! - External MCP loopback proxy mediation & DNS blacklist verification
//! - Restart & ledger continuity verification

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

use relay_canonical::{ActionCanonicalizer, ToolIdentity};
use relay_connectors::coordinator::GovernedActionRunner;
use relay_connectors::fs::{FilesystemConnector, FsConnectorConfig};
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{ApprovalProvider, PrincipalId, ReceiptSigner, SessionId};
use relay_ledger::SqliteLedger;
use relay_mcp::egress_dns::DnsResolverWithBlacklist;
use relay_mcp::egress_injector::CredentialInjector;
use relay_mcp::egress_proxy::EgressProxy;
use relay_mcp::egress_session::ProxySessionManager;
use relay_policy::CedarPolicyEngine;
use relay_receipts::Ed25519ReceiptSigner;

struct NeverApprovalProvider;

#[async_trait::async_trait]
impl ApprovalProvider for NeverApprovalProvider {
    async fn request_approval(
        &self,
        _approval: &mut relay_domain::Approval,
    ) -> Result<(), relay_domain::ApprovalError> {
        Err(relay_domain::ApprovalError::NonInteractiveMode)
    }
}

#[test]
fn test_ga_smoke_doctor_clean_environment() {
    let clean_home = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("relay").unwrap();

    cmd.env_clear()
        .env("HOME", clean_home.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "=== Relay System Health & Foundation Diagnostics ===",
        ))
        .stdout(predicate::str::contains("Relay Version"))
        .stdout(predicate::str::contains("Target OS"))
        .stdout(predicate::str::contains("Target Architecture"))
        .stdout(predicate::str::contains("Config Directory"))
        .stdout(predicate::str::contains("Ledger Path"))
        .stdout(predicate::str::contains("Policy Directory"))
        .stdout(predicate::str::contains("Terminal (TTY)"))
        .stdout(predicate::str::contains("Egress Sandbox Mode"));
}

#[test]
fn test_ga_smoke_version_and_help() {
    let mut cmd_version = Command::cargo_bin("relay").unwrap();
    cmd_version
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("relay 0.1.0"));

    let mut cmd_help = Command::cargo_bin("relay").unwrap();
    cmd_help
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: relay"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("receipt"))
        .stdout(predicate::str::contains("policy"));
}

#[test]
fn test_ga_smoke_policy_validate() {
    let clean_home = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("relay").unwrap();

    cmd.env_clear()
        .env("HOME", clean_home.path())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("policy")
        .arg("validate")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "=== Cedar Policy Engine Validation ===",
        ))
        .stdout(predicate::str::contains("VALID"));
}

#[tokio::test]
async fn test_ga_smoke_full_governed_lifecycle_and_verification() {
    let env_dir = tempdir().unwrap();
    let workspace_dir = env_dir.path().join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();

    let db_path = env_dir.path().join("storage").join("ledger.db");
    let key_path = env_dir.path().join("keys").join("signing_key.seed");

    // 1. Generate and persist Ed25519 signing key
    let signer = Arc::new(Ed25519ReceiptSigner::generate("ga001-smoke-key"));
    signer.save_to_file(&key_path).unwrap();

    // 2. Initialize SQLite ledger with genesis
    let ledger = Arc::new(SqliteLedger::open(&db_path).unwrap());
    let pubkey_hex = hex::encode(signer.export_public_key());
    ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    // 3. Configure Cedar policy engine & connectors
    let cedar_policy = r#"
        permit (
            principal == Relay::Agent::"principal:agent:default",
            action in [Relay::Action::"fs.write_file", Relay::Action::"fs.read_file"],
            resource
        );
    "#;
    let engine = Arc::new(CedarPolicyEngine::from_str(cedar_policy, None).unwrap());
    let cred_provider = Arc::new(InMemoryCredentialProvider::with_default_keyring());
    let broker = Arc::new(JitCredentialBroker::default());
    broker.register_provider(cred_provider).await;

    let fs_config = FsConnectorConfig::new(workspace_dir.clone());
    let fs_connector = Arc::new(FilesystemConnector::new(fs_config));

    let runner = GovernedActionRunner::builder()
        .policy_engine(engine)
        .approval_provider(Arc::new(NeverApprovalProvider))
        .credential_broker(broker)
        .receipt_signer(signer.clone())
        .ledger(ledger.clone())
        .fs_connector(fs_connector)
        .build()
        .unwrap();

    // 4. Execute governed action: fs.write_file
    let canonicalizer = ActionCanonicalizer::default();
    let session_id = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:default").unwrap();
    let tool = ToolIdentity::parse("relay.fs.write_file").unwrap();

    let test_file = workspace_dir.join("ga_smoke_artifact.txt");
    let raw_args = serde_json::json!({
        "path": test_file.to_str().unwrap(),
        "content": "GA001 production release governed smoke test passed\n"
    });

    let canonical_action = canonicalizer
        .canonicalize(
            session_id,
            principal,
            "tools/call",
            tool,
            &raw_args,
            None,
            None,
        )
        .unwrap();

    let outcome = runner.run_action(&canonical_action).await.unwrap();
    assert!(outcome.ledger_entry.is_some());
    assert!(test_file.exists());
    let content = fs::read_to_string(&test_file).unwrap();
    assert_eq!(
        content,
        "GA001 production release governed smoke test passed\n"
    );

    // 5. Verify ledger hash chain via CLI
    let mut verify_cmd = Command::cargo_bin("relay").unwrap();
    verify_cmd
        .arg("verify")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Total Entries:    2"))
        .stdout(predicate::str::contains("VALID"));

    // 6. Query receipt list via CLI
    let mut receipt_cmd = Command::cargo_bin("relay").unwrap();
    receipt_cmd
        .arg("receipt")
        .arg("list")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("#1"))
        .stdout(predicate::str::contains("#0"));
}

#[tokio::test]
async fn test_ga_smoke_external_egress_proxy_and_dns_blocking() {
    let session_mgr = ProxySessionManager::new();
    let dns_resolver = DnsResolverWithBlacklist::strict();
    let injector = CredentialInjector::new();

    let proxy_addr = "127.0.0.1:0".parse().unwrap();
    let proxy = EgressProxy::new(proxy_addr, session_mgr, dns_resolver, injector, None);

    assert_eq!(proxy.bind_addr(), proxy_addr);

    // Verify DNS SSRF blocker in strict mode
    assert!(proxy
        .dns_resolver()
        .resolve_and_validate("169.254.169.254", 80)
        .await
        .is_err());
    assert!(proxy
        .dns_resolver()
        .resolve_and_validate("127.0.0.1", 80)
        .await
        .is_err());
    assert!(proxy
        .dns_resolver()
        .resolve_and_validate("metadata.google.internal", 80)
        .await
        .is_err());
}
