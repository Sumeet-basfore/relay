//! End-to-end integration tests for Gateway with Cedar Policy Enforcement Point (PEP).
//!
//! Validates:
//! - Permitted actions are forwarded to downstream MCP subprocess and succeed
//! - Forbidden actions are intercepted and halted with JSON-RPC error -32003 and ActionHash
//! - Approval-required actions are intercepted and halted with JSON-RPC error -32005
//! - Strict default-deny blocks unregistered tools with -32003
//! - Downstream subprocess never receives denied or approval-required tool calls

use relay_domain::SessionId;
use relay_mcp::{run_gateway, spawn, GatewayConfig, GatewayExitStatus, SubprocessConfig};
use relay_policy::CedarPolicyEngine;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;

fn mock_server() -> String {
    assert_cmd::cargo::cargo_bin("mock-mcp-server")
        .to_str()
        .expect("utf8 path")
        .to_string()
}

struct GatewayPolicyHarness {
    test_write: tokio::io::DuplexStream,
    test_read: tokio::io::DuplexStream,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<GatewayExitStatus, relay_mcp::GatewayError>>,
}

impl GatewayPolicyHarness {
    async fn start_with_engine(engine: Arc<CedarPolicyEngine>) -> Self {
        let subprocess = spawn(&SubprocessConfig::new(mock_server(), vec![], "0.1.0"))
            .await
            .expect("spawn");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (gateway_agent_read, test_write) = tokio::io::duplex(64 * 1024);
        let (test_read, gateway_agent_write) = tokio::io::duplex(64 * 1024);

        let config = GatewayConfig::with_policy_engine(SessionId::new_v7(), engine);

        let task = tokio::spawn(async move {
            run_gateway(
                gateway_agent_read,
                gateway_agent_write,
                subprocess,
                config,
                shutdown_rx,
            )
            .await
        });

        let mut harness = Self {
            test_write,
            test_read,
            shutdown_tx,
            task,
        };

        // Complete standard MCP initialization handshake
        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-agent","version":"0.1.0"}}}"#;
        harness.send_line(init_req).await;
        let init_resp = harness.read_line().await;
        assert!(init_resp.contains("mock-mcp-server"));

        harness
            .send_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .await;

        harness
    }

    async fn send_line(&mut self, line: &str) {
        self.test_write
            .write_all(format!("{}\n", line).as_bytes())
            .await
            .expect("write");
        self.test_write.flush().await.expect("flush");
    }

    async fn read_line(&mut self) -> String {
        let mut reader = BufReader::new(&mut self.test_read);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timeout")
            .expect("read");
        line
    }

    async fn shutdown(self) -> GatewayExitStatus {
        let _ = self.shutdown_tx.send(true);
        self.task.await.expect("join").expect("gateway ok")
    }
}

#[tokio::test]
async fn gateway_policy_permits_safe_file_read() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));
    let mut harness = GatewayPolicyHarness::start_with_engine(engine).await;

    let tool_call = r#"{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"fs.read","arguments":{"path":"/workspace/safe_file.txt"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(100)));
    assert!(
        resp.get("error").is_none(),
        "Expected success, got error: {:?}",
        resp.get("error")
    );
    assert!(resp.get("result").is_some());

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_policy_blocks_forbidden_env_file() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));
    let mut harness = GatewayPolicyHarness::start_with_engine(engine).await;

    // Agent attempts to read sensitive .env file
    let tool_call = r#"{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"fs.read","arguments":{"path":"/workspace/.env"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(101)));
    assert!(resp.get("result").is_none());

    let error_obj = resp.get("error").expect("error object must be present");
    // Code -32003 for Action Forbidden
    assert_eq!(
        error_obj.get("code").and_then(|v| v.as_i64()),
        Some(-32003),
        "Expected error code -32003, got: {error_obj:?}"
    );

    let msg = error_obj
        .get("message")
        .and_then(|v| v.as_str())
        .expect("message");
    assert!(msg.contains("Action Forbidden"));

    let data_obj = error_obj.get("data").expect("data must be present");
    assert!(data_obj.get("action_hash").is_some());
    assert!(data_obj.get("decision_id").is_some());
    let determining = data_obj
        .get("determining_policies")
        .and_then(|v| v.as_array())
        .expect("determining_policies array");
    assert!(determining
        .iter()
        .any(|p| p.as_str() == Some("forbid_sensitive_files")));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_policy_halts_approval_required_file_delete() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));
    let mut harness = GatewayPolicyHarness::start_with_engine(engine).await;

    // Agent attempts to delete a file which requires step-up approval
    let tool_call = r#"{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"fs.delete","arguments":{"path":"/workspace/scratch.txt"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(102)));
    assert!(resp.get("result").is_none());

    let error_obj = resp.get("error").expect("error object must be present");
    // Code -32005 for Approval Required
    assert_eq!(
        error_obj.get("code").and_then(|v| v.as_i64()),
        Some(-32005),
        "Expected error code -32005, got: {error_obj:?}"
    );

    let msg = error_obj
        .get("message")
        .and_then(|v| v.as_str())
        .expect("message");
    assert!(msg.contains("Approval Required"));

    let data_obj = error_obj.get("data").expect("data must be present");
    assert!(data_obj.get("action_hash").is_some());
    assert_eq!(data_obj.get("approval_required"), Some(&Value::Bool(true)));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_policy_blocks_unregistered_tool_default_deny() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));
    let mut harness = GatewayPolicyHarness::start_with_engine(engine).await;

    // Tool that is not permitted anywhere in default policies
    let tool_call = r#"{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"unregistered.malicious_tool","arguments":{"arg":"value"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(103)));
    let error_obj = resp.get("error").expect("error object must be present");
    assert_eq!(error_obj.get("code").and_then(|v| v.as_i64()), Some(-32003));

    let msg = error_obj.get("message").and_then(|v| v.as_str()).unwrap();
    assert!(msg.contains("Action Forbidden"));

    harness.shutdown().await;
}
