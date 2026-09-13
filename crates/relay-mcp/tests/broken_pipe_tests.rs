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

struct TestHarness {
    test_write: Option<tokio::io::DuplexStream>,
    test_read: Option<tokio::io::DuplexStream>,
    #[allow(dead_code)]
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<GatewayExitStatus, relay_mcp::GatewayError>>,
}

impl TestHarness {
    async fn start_with_args(
        args: Vec<String>,
        startup_timeout: Duration,
        grace_period: Duration,
    ) -> Self {
        let mut subproc_config = SubprocessConfig::new(mock_server(), args, "0.1.0");
        subproc_config.startup_timeout = startup_timeout;
        subproc_config.shutdown_grace_period = grace_period;

        let subprocess = spawn(&subproc_config).await.expect("spawn mock server");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (gateway_agent_read, test_write) = tokio::io::duplex(64 * 1024);
        let (test_read, gateway_agent_write) = tokio::io::duplex(64 * 1024);

        let mut config = GatewayConfig::with_pass_through(SessionId::new_v7());
        config.startup_timeout = startup_timeout;
        config.shutdown_grace_period = grace_period;

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
            test_write: Some(test_write),
            test_read: Some(test_read),
            shutdown_tx,
            task,
        }
    }

    async fn send_line(&mut self, line: &str) {
        if let Some(ref mut write) = self.test_write {
            write
                .write_all(format!("{}\n", line).as_bytes())
                .await
                .expect("write");
            write.flush().await.expect("flush");
        }
    }

    async fn read_line(&mut self) -> String {
        let read = self.test_read.as_mut().expect("test_read is open");
        let mut reader = BufReader::new(read);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timeout waiting for line")
            .expect("read line");
        line
    }

    fn drop_agent_stdout(&mut self) {
        self.test_read = None;
    }

    fn drop_agent_stdin(&mut self) {
        self.test_write = None;
    }
}

/// 1. Agent stdout consumer disappears while child/relay tries to write
#[tokio::test]
async fn test_broken_pipe_agent_stdout_consumer_disappears() {
    let mut harness =
        TestHarness::start_with_args(vec![], Duration::from_secs(5), Duration::from_millis(500))
            .await;

    // Drop the agent reader end (agent closed its stdout consumer)
    harness.drop_agent_stdout();

    // Send an initialize request that produces a response
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(req).await;

    // The gateway must terminate cleanly and not hang indefinitely
    let res = tokio::time::timeout(Duration::from_secs(5), harness.task)
        .await
        .expect("gateway hung on agent stdout consumer disappearing")
        .expect("join handle failed");

    assert!(res.is_ok());
}

/// 2. Agent stdin closes (EOF)
#[tokio::test]
async fn test_broken_pipe_agent_stdin_closing() {
    let mut harness =
        TestHarness::start_with_args(vec![], Duration::from_secs(5), Duration::from_millis(500))
            .await;

    // Close agent stdin
    harness.drop_agent_stdin();

    // Gateway must detect EOF, signal EOF to child, and exit cleanly
    let res = tokio::time::timeout(Duration::from_secs(5), harness.task)
        .await
        .expect("gateway hung on agent stdin close")
        .expect("join handle failed");

    let status = res.expect("gateway exit status ok");
    assert!(status.child_exit_code.is_none() || status.child_exit_code == Some(0));
}

/// 3. Child stdin closing early
#[tokio::test]
async fn test_broken_pipe_child_stdin_closing() {
    let mut harness = TestHarness::start_with_args(
        vec!["--close-stdin-early".into()],
        Duration::from_secs(5),
        Duration::from_millis(500),
    )
    .await;

    // Small yield to let child close stdin
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send request into closed child stdin
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(req).await;

    // Gateway must detect broken pipe on child stdin and exit cleanly
    let res = tokio::time::timeout(Duration::from_secs(5), harness.task)
        .await
        .expect("gateway hung on child stdin broken pipe")
        .expect("join handle failed");

    assert!(res.is_ok());
}

/// 4. Child stdout closing early
#[tokio::test]
async fn test_broken_pipe_child_stdout_closing() {
    let harness = TestHarness::start_with_args(
        vec!["--close-stdout-early".into()],
        Duration::from_secs(5),
        Duration::from_millis(500),
    )
    .await;

    // Gateway must detect child stdout EOF and terminate cleanly without hanging
    let res = tokio::time::timeout(Duration::from_secs(5), harness.task)
        .await
        .expect("gateway hung on child stdout closing")
        .expect("join handle failed");

    assert!(res.is_ok());
}

/// 5. Child exiting during an active in-flight request
#[tokio::test]
async fn test_broken_pipe_child_exiting_during_active_request() {
    let mut harness = TestHarness::start_with_args(
        vec!["--exit-on-request".into(), "tools/call".into()],
        Duration::from_secs(5),
        Duration::from_millis(500),
    )
    .await;

    // Initialize first
    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    harness.send_line(init_req).await;
    let init_resp = harness.read_line().await;
    assert!(init_resp.contains("mock-mcp-server"));

    // Now send tools/call, which causes the mock child to exit immediately
    let tool_req = r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"crash"}}}"#;
    harness.send_line(tool_req).await;

    // The gateway must return error -32011 to agent for request ID 42 and exit cleanly
    let line = harness.read_line().await;
    let val: Value = serde_json::from_str(line.trim()).expect("valid json error response");
    assert_eq!(val.get("id"), Some(&Value::from(42)));
    assert!(val.get("error").is_some());
    let err_code = val["error"]["code"].as_i64().expect("error code");
    assert_eq!(err_code, -32011); // A001 line 917: Downstream MCP Subprocess Terminated

    let res = tokio::time::timeout(Duration::from_secs(5), harness.task)
        .await
        .expect("gateway hung after child exited mid-request")
        .expect("join handle failed");

    let status = res.expect("gateway exit status ok");
    assert_eq!(status.child_exit_code, Some(44));
}
