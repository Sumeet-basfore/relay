use relay_domain::SessionId;
use relay_mcp::{run_gateway, spawn, GatewayConfig, GatewayExitStatus, SubprocessConfig};
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;

fn mock_server() -> String {
    assert_cmd::cargo::cargo_bin("mock-mcp-server")
        .to_str()
        .expect("utf8 path")
        .to_string()
}

struct GatewayHarness {
    test_write: tokio::io::DuplexStream,
    test_read: tokio::io::DuplexStream,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<GatewayExitStatus, relay_mcp::GatewayError>>,
}

impl GatewayHarness {
    async fn start(max_frame_bytes: usize) -> Self {
        let subprocess = spawn(&SubprocessConfig::new(mock_server(), vec![], "0.1.0"))
            .await
            .expect("spawn");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (gateway_agent_read, test_write) = tokio::io::duplex(64 * 1024);
        let (test_read, gateway_agent_write) = tokio::io::duplex(64 * 1024);

        let mut config = GatewayConfig::with_pass_through(SessionId::new_v7());
        config.max_frame_bytes = max_frame_bytes;

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

        Self {
            test_write,
            test_read,
            shutdown_tx,
            task,
        }
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
async fn gateway_forwards_initialize() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(request).await;
    let line = harness.read_line().await;
    assert!(line.contains("mock-mcp-server"));
    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_forwards_initialized_notification() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(init).await;
    let _ = harness.read_line().await;

    harness
        .send_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;

    harness
        .send_line(r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#)
        .await;
    let ping = harness.read_line().await;
    let value: Value = serde_json::from_str(ping.trim()).expect("json");
    assert_eq!(value.get("id"), Some(&Value::from(2)));
    assert!(value.get("result").is_some());

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_tools_call_echo_roundtrip() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(init).await;
    let _ = harness.read_line().await;

    let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello"}}}"#;
    harness.send_line(call).await;
    let line = harness.read_line().await;
    assert!(line.contains("hello"));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_oversized_frame_returns_error() {
    let mut harness = GatewayHarness::start(32).await;
    let oversized = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":9,\"data\":\"{}\"}}",
        "x".repeat(64)
    );
    harness.send_line(&oversized).await;
    let line = harness.read_line().await;
    let value: Value = serde_json::from_str(line.trim()).expect("json");
    assert!(value.get("error").is_some());
    assert_eq!(value.get("id"), Some(&Value::Null));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_malformed_json_returns_error() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;
    harness.send_line("{not-json").await;
    let line = harness.read_line().await;
    let value: Value = serde_json::from_str(line.trim()).expect("json");
    assert!(value.get("error").is_some());
    let code = value["error"]["code"].as_i64().expect("code");
    assert_eq!(code, -32700);

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_invalid_tools_call_returns_error() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;
    let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"arguments":{}}}"#;
    harness.send_line(call).await;
    let line = harness.read_line().await;
    let value: Value = serde_json::from_str(line.trim()).expect("json");
    assert!(value.get("error").is_some());
    assert_eq!(value.get("id"), Some(&Value::from(7)));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_subprocess_exits_cleanly_on_agent_eof() {
    let harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;

    drop(harness.test_write);

    let result = tokio::time::timeout(Duration::from_secs(5), harness.task)
        .await
        .expect("timeout")
        .expect("join")
        .expect("gateway ok");

    assert!(result.child_exit_code.is_none() || result.child_exit_code == Some(0));
}

#[tokio::test]
async fn gateway_rejects_duplicate_keys_in_tool_call() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(init).await;
    let _ = harness.read_line().await;

    // Tool call containing duplicate "path" keys
    let call = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fs.read_file","arguments":{"path":"/safe","path":"/etc/passwd"}}}"#;
    harness.send_line(call).await;
    let line = harness.read_line().await;
    let value: Value = serde_json::from_str(line.trim()).expect("json");

    assert!(value.get("error").is_some());
    let code = value["error"]["code"].as_i64().expect("code");
    assert_eq!(code, -32700); // Parse error for duplicate keys
    let msg = value["error"]["message"].as_str().expect("message");
    assert!(msg.contains("Duplicate JSON key 'path'"));

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_rejects_path_traversal_in_tool_call() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(init).await;
    let _ = harness.read_line().await;

    // Tool call with null byte in path
    let call = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"fs.read_file","arguments":{"path":"/safe\u0000/evil"}}}"#;
    harness.send_line(call).await;
    let line = harness.read_line().await;
    let value: Value = serde_json::from_str(line.trim()).expect("json");

    assert!(value.get("error").is_some());
    let code = value["error"]["code"].as_i64().expect("code");
    assert_eq!(code, -32602); // InvalidParams for path error

    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_rejects_multi_statement_sql_in_tool_call() {
    let mut harness = GatewayHarness::start(relay_mcp::MAX_FRAME_SIZE_BYTES).await;

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(init).await;
    let _ = harness.read_line().await;

    // Tool call with multi-statement SQL injection
    let call = r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"sql.query","arguments":{"query":"SELECT 1; DROP TABLE users;"}}}"#;
    harness.send_line(call).await;
    let line = harness.read_line().await;
    let value: Value = serde_json::from_str(line.trim()).expect("json");

    assert!(value.get("error").is_some());
    let code = value["error"]["code"].as_i64().expect("code");
    assert_eq!(code, -32602); // InvalidParams for multi-statement SQL rejection
    let msg = value["error"]["message"].as_str().expect("message");
    assert!(msg.contains("Multi-statement SQL batching rejected"));

    harness.shutdown().await;
}
