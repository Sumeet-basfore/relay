use serde_json::{json, Value};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use tokio::sync::{watch, RwLock};

use relay_cli::config::RelayConfig;
use relay_cli::ui::{SessionManager, UiServer, UiState};
use relay_domain::ReceiptSigner;
use relay_ledger::SqliteLedger;
use relay_receipts::Ed25519ReceiptSigner;

#[allow(dead_code)]
struct TestServer {
    pub port: u16,
    pub base_url: String,
    pub bootstrap_token: String,
    pub shutdown_tx: watch::Sender<bool>,
    pub signer: Arc<Ed25519ReceiptSigner>,
    pub ledger: Arc<SqliteLedger>,
    pub _temp_dir: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

async fn start_test_server() -> TestServer {
    // 1. Pick a free port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let base_url = format!("http://127.0.0.1:{port}");

    // 2. Temp ledger
    let temp_dir = tempfile::tempdir().unwrap();
    let ledger_path = temp_dir.path().join("ledger.db");

    let ledger = SqliteLedger::open(&ledger_path).unwrap();
    let signer = Arc::new(Ed25519ReceiptSigner::generate("relay-test-signer-v1"));

    let pubkey_bytes = signer.export_public_key();
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    let _ = ledger
        .initialize_genesis(
            "01918a20-4321-7000-8000-000000000001",
            &hex::encode(pubkey_bytes),
        )
        .await;

    let bootstrap_token = "test_bootstrap_secret_token_123456789".to_string();
    let session_manager = Arc::new(RwLock::new(SessionManager::new(Some(
        bootstrap_token.clone(),
    ))));

    let engine = relay_policy::CedarPolicyEngine::default_engine().unwrap();

    let mut config = RelayConfig::default();
    config.storage.ledger_path = ledger_path;

    let state = UiState {
        session_manager,
        config,
        ledger: Arc::new(ledger.clone()),
        policy_engine: Arc::new(RwLock::new(Arc::new(engine))),
        signing_key_id: "relay-test-signer-v1".to_string(),
        signer_pubkey: Some(pubkey_arr),
        port,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = UiServer::new(state, bind_addr);

    tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    TestServer {
        port,
        base_url,
        bootstrap_token,
        shutdown_tx,
        signer,
        ledger: Arc::new(ledger),
        _temp_dir: temp_dir,
    }
}

/// Helper to authenticate and obtain (session_token, csrf_token)
async fn get_authenticated_session(server: &TestServer) -> (String, String) {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/api/v1/auth/session", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .json(&json!({ "token": server.bootstrap_token }))
        .send()
        .await
        .expect("send auth request");

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let session_token = body["session_token"].as_str().unwrap().to_string();
    let csrf_token = body["csrf_token"].as_str().unwrap().to_string();
    (session_token, csrf_token)
}

// -----------------------------------------------------------------------------
// 1. Authentication & Session Security Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_unauthenticated_request_rejected() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/status", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_invalid_bootstrap_token_rejected() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{}/api/v1/auth/session", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .json(&json!({ "token": "invalid_wrong_token" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn test_authenticated_status_query() {
    let server = start_test_server().await;
    let (session_token, _) = get_authenticated_session(&server).await;

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/api/v1/status", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["security_status"], "PROTECTED");
    assert_eq!(body["active_connectors"], 4);
    assert_eq!(body["signing_key_id"], "relay-test-signer-v1");
}

// -----------------------------------------------------------------------------
// 2. DNS Rebinding & Host Header Validation Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_rebinding_rejected() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Attacker sends request through evil.com pointing to 127.0.0.1
    let res = client
        .get(format!("{}/api/v1/status", server.base_url))
        .header("Host", format!("attacker.com:{}", server.port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);
    let text = res.text().await.unwrap();
    assert!(text.contains("Host header does not match"));
}

// -----------------------------------------------------------------------------
// 3. CSRF & Origin Validation Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_csrf_protection_on_mutating_endpoint() {
    let server = start_test_server().await;
    let (session_token, _) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    // POST without CSRF header
    let res = client
        .post(format!("{}/api/v1/policies/reload", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .header("Origin", format!("http://127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);
    let text = res.text().await.unwrap();
    assert!(text.contains("Missing X-Relay-CSRF"));
}

#[tokio::test]
async fn test_cross_origin_mutating_request_blocked() {
    let server = start_test_server().await;
    let (session_token, csrf_token) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    // POST with malicious origin
    let res = client
        .post(format!("{}/api/v1/policies/reload", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .header("X-Relay-CSRF", &csrf_token)
        .header("Origin", "http://evil-attacker-site.com")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);
    let text = res.text().await.unwrap();
    assert!(text.contains("Origin header does not match"));
}

// -----------------------------------------------------------------------------
// 4. Content Security Policy & Security Headers Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_security_headers_present() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let headers = res.headers();

    assert!(headers.get("content-security-policy").is_some());
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));

    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "no-store, no-cache, must-revalidate, max-age=0"
    );
}

// -----------------------------------------------------------------------------
// 5. Embedded Static Assets Test (Zero Remote CDN Dependency)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_static_assets_served_locally() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // 1. index.html
    let res_html = client
        .get(format!("{}/", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res_html.status(), 200);
    let body_html = res_html.text().await.unwrap();
    assert!(body_html.contains("Relay Security Console"));
    assert!(!body_html.contains("https://cdn"));
    assert!(!body_html.contains("http://"));

    // 2. app.css
    let res_css = client
        .get(format!("{}/assets/app.css", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res_css.status(), 200);
    assert_eq!(
        res_css.headers().get("content-type").unwrap(),
        "text/css; charset=utf-8"
    );

    // 3. app.js
    let res_js = client
        .get(format!("{}/assets/app.js", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res_js.status(), 200);
    assert_eq!(
        res_js.headers().get("content-type").unwrap(),
        "application/javascript; charset=utf-8"
    );

    // 4. favicon.svg
    let res_svg = client
        .get(format!("{}/assets/favicon.svg", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res_svg.status(), 200);
    assert_eq!(
        res_svg.headers().get("content-type").unwrap(),
        "image/svg+xml"
    );
}

// -----------------------------------------------------------------------------
// 6. Security Boundary Enforcement: No Raw Execution or Credential Endpoints
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_no_raw_connector_execution_endpoints() {
    let server = start_test_server().await;
    let (session_token, csrf_token) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    let paths = [
        "/api/v1/execute",
        "/api/v1/connectors/exec",
        "/api/v1/fs/delete",
        "/api/v1/postgres/query",
        "/api/v1/credentials/raw",
        "/api/v1/secrets/get",
    ];

    for path in paths {
        let res = client
            .post(format!("{}{}", server.base_url, path))
            .header("Host", format!("127.0.0.1:{}", server.port))
            .header("X-Relay-Session", &session_token)
            .header("X-Relay-CSRF", &csrf_token)
            .header("Origin", format!("http://127.0.0.1:{}", server.port))
            .json(&json!({ "cmd": "rm -rf /" }))
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 404, "Endpoint {path} must not exist!");
    }
}

// -----------------------------------------------------------------------------
// 7. Policy Validation and Atomic Reload Safety Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_policy_validate_valid_syntax() {
    let server = start_test_server().await;
    let (session_token, csrf_token) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    let valid_cedar = r#"
        permit(
            principal == Relay::Agent::"agent-01",
            action == Relay::Action::"fs.read",
            resource == Relay::Resource::"file:///test.txt"
        );
    "#;

    let res = client
        .post(format!("{}/api/v1/policies/validate", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .header("X-Relay-CSRF", &csrf_token)
        .header("Origin", format!("http://127.0.0.1:{}", server.port))
        .json(&json!({ "policy_text": valid_cedar }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["is_valid"], true);
    assert_eq!(body["policy_count"], 1);
}

#[tokio::test]
async fn test_policy_validate_invalid_syntax() {
    let server = start_test_server().await;
    let (session_token, csrf_token) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    let invalid_cedar = "this is total garbage not cedar syntax!";

    let res = client
        .post(format!("{}/api/v1/policies/validate", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .header("X-Relay-CSRF", &csrf_token)
        .header("Origin", format!("http://127.0.0.1:{}", server.port))
        .json(&json!({ "policy_text": invalid_cedar }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["is_valid"], false);
    assert!(body["error"].as_str().is_some());
}

// -----------------------------------------------------------------------------
// 8. Cryptographic Ledger & Receipt Verification Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_ledger_verification_endpoint() {
    let server = start_test_server().await;
    let (session_token, csrf_token) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{}/api/v1/ledger/verify", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .header("X-Relay-CSRF", &csrf_token)
        .header("Origin", format!("http://127.0.0.1:{}", server.port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["is_valid"], true);
    assert_eq!(body["total_verified_entries"], 1); // genesis entry
}

// -----------------------------------------------------------------------------
// 9. Data Minimization & Secret Redaction Tests
// -----------------------------------------------------------------------------

#[test]
fn test_data_minimization_redacts_credentials() {
    use relay_cli::ui::data_minimization::sanitize_json_value;

    let payload = json!({
        "tool": "github.read",
        "parameters": {
            "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "repo": "owner/repo",
            "db_pass": "SuperSecretPass123!",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        }
    });

    let sanitized = sanitize_json_value(&payload);
    assert_eq!(sanitized["parameters"]["token"], "[REDACTED]");
    assert_eq!(sanitized["parameters"]["db_pass"], "[REDACTED]");
    assert_eq!(sanitized["parameters"]["private_key"], "[REDACTED]");
    assert_eq!(sanitized["parameters"]["repo"], "owner/repo");
}

// -----------------------------------------------------------------------------
// 10. Request Body Limits (DoS Defense)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_oversized_payload_rejected() {
    let server = start_test_server().await;
    let (session_token, csrf_token) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    // 2 MB body (exceeds 1 MB MAX_BODY_SIZE)
    let huge_body = vec![b'a'; 2 * 1024 * 1024];

    let res = client
        .post(format!("{}/api/v1/policies/validate", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .header("X-Relay-CSRF", &csrf_token)
        .header("Origin", format!("http://127.0.0.1:{}", server.port))
        .body(huge_body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 413); // Payload Too Large
}

// -----------------------------------------------------------------------------
// 11. Doctor Report Integration Test (Shared Single Source of Truth)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_doctor_endpoint_matches_cli_report() {
    let server = start_test_server().await;
    let (session_token, _) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{}/api/v1/doctor", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let doc: Value = res.json().await.unwrap();
    assert_eq!(doc["relay_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(doc["target_os"], std::env::consts::OS);
    assert_eq!(doc["is_healthy"], true);
    assert!(doc["status_message"]
        .as_str()
        .unwrap()
        .contains("Operational"));
}

// -----------------------------------------------------------------------------
// 12. Connectors & Egress Visibility Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_connectors_and_egress_endpoints() {
    let server = start_test_server().await;
    let (session_token, _) = get_authenticated_session(&server).await;
    let client = reqwest::Client::new();

    // 1. Connectors
    let res_c = client
        .get(format!("{}/api/v1/connectors", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .send()
        .await
        .unwrap();

    assert_eq!(res_c.status(), 200);
    let conn: Value = res_c.json().await.unwrap();
    let list = conn["connectors"].as_array().unwrap();
    assert_eq!(list.len(), 4);
    assert!(list.iter().any(|c| c["name"] == "Filesystem Connector"));
    assert!(list.iter().any(|c| c["name"] == "PostgreSQL Connector"));

    // 2. Egress
    let res_e = client
        .get(format!("{}/api/v1/egress", server.base_url))
        .header("Host", format!("127.0.0.1:{}", server.port))
        .header("X-Relay-Session", &session_token)
        .send()
        .await
        .unwrap();

    assert_eq!(res_e.status(), 200);
    let egress: Value = res_e.json().await.unwrap();
    assert_eq!(egress["proxy_status"], "RUNNING");
    let blocked = egress["blocked_attempts"].as_array().unwrap();
    assert!(!blocked.is_empty());
    assert!(blocked[0]["destination"]
        .as_str()
        .unwrap()
        .contains("169.254.169.254"));
}
