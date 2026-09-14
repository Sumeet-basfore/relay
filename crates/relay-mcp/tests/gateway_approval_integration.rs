//! End-to-end integration tests for Gateway with Cedar Policy and Human Approval Provider (B011).
//!
//! Validates:
//! - When approval is required and approved via TTY: forwarded downstream and succeeds
//! - When approval is required and denied via TTY: rejected with JSON-RPC error -32001
//! - When approval is required in headless mode: rejected with JSON-RPC error -32005 and exit_code 7

use relay_domain::{ApprovalProvider, SessionId};
use relay_mcp::approval::headless::HeadlessApprovalGate;
use relay_mcp::approval::tty::TtyApprovalProvider;
use relay_mcp::{run_gateway, spawn, GatewayConfig, GatewayExitStatus, SubprocessConfig};
use relay_policy::CedarPolicyEngine;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;

fn mock_server() -> String {
    assert_cmd::cargo::cargo_bin("mock-mcp-server")
        .to_str()
        .expect("utf8 path")
        .to_string()
}

struct GatewayApprovalHarness {
    test_write: tokio::io::DuplexStream,
    test_read: tokio::io::DuplexStream,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<GatewayExitStatus, relay_mcp::GatewayError>>,
}

impl GatewayApprovalHarness {
    async fn start_with_approval(
        engine: Arc<CedarPolicyEngine>,
        provider: Arc<dyn ApprovalProvider>,
    ) -> Self {
        let subprocess = spawn(&SubprocessConfig::new(mock_server(), vec![], "0.1.0"))
            .await
            .expect("spawn");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (gateway_agent_read, test_write) = tokio::io::duplex(64 * 1024);
        let (test_read, gateway_agent_write) = tokio::io::duplex(64 * 1024);

        let config = GatewayConfig::with_policy_and_approval(SessionId::new_v7(), engine, provider);

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
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write_all");
        self.test_write.flush().await.expect("flush");
    }

    async fn read_line(&mut self) -> String {
        let mut reader = BufReader::new(&mut self.test_read);
        let mut buf = String::new();
        reader.read_line(&mut buf).await.expect("read_line");
        buf
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        drop(self.test_write);
        let _ = self.task.await;
    }
}

#[tokio::test]
async fn gateway_approves_file_delete_on_operator_yes() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));

    // TTY provider that inputs 'y'
    let tty_in = b"y\n";
    let tty_out = Vec::new();
    let provider = Arc::new(TtyApprovalProvider::with_mock_streams(
        tokio::io::BufReader::new(&tty_in[..]),
        tty_out,
        None,
    ));

    let mut harness = GatewayApprovalHarness::start_with_approval(engine, provider).await;

    // Agent invokes fs.delete (requires approval by policy)
    let tool_call = r#"{"jsonrpc":"2.0","id":201,"method":"tools/call","params":{"name":"fs.delete","arguments":{"path":"/workspace/scratch.txt"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(201)));
    // Tool call was approved and forwarded, downstream returned result
    assert!(resp.get("result").is_some());
    assert!(resp.get("error").is_none());

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_rejects_file_delete_on_operator_no() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));

    // TTY provider that inputs 'n'
    let tty_in = b"n\n";
    let tty_out = Vec::new();
    let provider = Arc::new(TtyApprovalProvider::with_mock_streams(
        tokio::io::BufReader::new(&tty_in[..]),
        tty_out,
        None,
    ));

    let mut harness = GatewayApprovalHarness::start_with_approval(engine, provider).await;

    let tool_call = r#"{"jsonrpc":"2.0","id":202,"method":"tools/call","params":{"name":"fs.delete","arguments":{"path":"/workspace/scratch.txt"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(202)));
    assert!(resp.get("result").is_none());

    let error_obj = resp.get("error").expect("error object must be present");
    // Code -32001 for operator denial
    assert_eq!(error_obj.get("code").and_then(|v| v.as_i64()), Some(-32001));

    let msg = error_obj.get("message").and_then(|v| v.as_str()).unwrap();
    assert!(msg.contains("rejected by operator approval policy"));

    let data = error_obj.get("data").expect("data object");
    assert_eq!(data.get("denied_by_human"), Some(&Value::Bool(true)));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_headless_gate_blocks_approval_required() {
    let engine = Arc::new(CedarPolicyEngine::default_engine().expect("default engine"));
    let provider = Arc::new(HeadlessApprovalGate::new());

    let mut harness = GatewayApprovalHarness::start_with_approval(engine, provider).await;

    let tool_call = r#"{"jsonrpc":"2.0","id":203,"method":"tools/call","params":{"name":"fs.delete","arguments":{"path":"/workspace/scratch.txt"}}}"#;
    harness.send_line(tool_call).await;

    let response_line = harness.read_line().await;
    let resp: Value = serde_json::from_str(&response_line).expect("valid json");

    assert_eq!(resp.get("id"), Some(&Value::from(203)));
    assert!(resp.get("result").is_none());

    let error_obj = resp.get("error").expect("error object must be present");
    // Code -32005 for headless blocked
    assert_eq!(error_obj.get("code").and_then(|v| v.as_i64()), Some(-32005));

    let data = error_obj.get("data").expect("data object");
    assert_eq!(data.get("headless_blocked"), Some(&Value::Bool(true)));
    assert_eq!(data.get("exit_code"), Some(&Value::from(7)));

    harness.shutdown().await;
}
