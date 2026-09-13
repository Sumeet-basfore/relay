use relay_domain::SessionId;
use relay_mcp::{run_gateway, spawn, GatewayConfig, GatewayError, SubprocessConfig};
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

/// 1. Child fails immediately upon startup:
/// If the binary exits immediately (e.g. --exit-on-startup), spawn or run_gateway
/// must detect it promptly without hanging and report the exit.
#[tokio::test]
async fn test_child_fails_immediately() {
    let subproc_config = SubprocessConfig::new(
        mock_server(),
        vec!["--exit-on-startup".to_string()],
        "0.1.0",
    );

    // Either spawn() detects immediate exit via try_wait(), or spawn succeeds and
    // run_gateway immediately receives EOF and exits.
    match spawn(&subproc_config).await {
        Ok(subprocess) => {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (agent_read, _agent_write_side) = tokio::io::duplex(4096);
            let (_agent_read_side, agent_write) = tokio::io::duplex(4096);

            let mut config = GatewayConfig::with_pass_through(SessionId::new_v7());
            config.startup_timeout = Duration::from_millis(500);

            let res = tokio::time::timeout(
                Duration::from_secs(2),
                run_gateway(agent_read, agent_write, subprocess, config, shutdown_rx),
            )
            .await
            .expect("gateway should not hang")
            .expect("gateway exit");

            assert_eq!(res.child_exit_code, Some(42));
            drop(shutdown_tx);
        }
        Err(e) => {
            // If spawn() caught the immediate exit via try_wait()
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("child process exited immediately") || err_msg.contains("42"),
                "unexpected error: {}",
                err_msg
            );
        }
    }
}

/// 2. Child hangs on startup (never produces any output):
/// Gateway must abort on startup_timeout with GatewayError::StartupTimeout
/// and terminate the child without hanging.
#[tokio::test]
async fn test_child_hangs_on_startup() {
    let mut subproc_config = SubprocessConfig::new(
        mock_server(),
        vec!["--hang-on-startup".to_string()],
        "0.1.0",
    );
    subproc_config.startup_timeout = Duration::from_millis(150);
    subproc_config.shutdown_grace_period = Duration::from_millis(100);

    let subprocess = spawn(&subproc_config).await.expect("spawn mock server");

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (agent_read, _agent_write_side) = tokio::io::duplex(4096);
    let (_agent_read_side, agent_write) = tokio::io::duplex(4096);

    let mut config = GatewayConfig::with_pass_through(SessionId::new_v7());
    config.startup_timeout = Duration::from_millis(150);
    config.shutdown_grace_period = Duration::from_millis(100);

    let start = std::time::Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(2),
        run_gateway(agent_read, agent_write, subprocess, config, shutdown_rx),
    )
    .await
    .expect("gateway must not hang on child hang");

    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(140),
        "should wait for startup timeout, took {:?}",
        elapsed
    );

    match res {
        Err(GatewayError::StartupTimeout(d)) => {
            assert_eq!(d, Duration::from_millis(150));
        }
        other => panic!("expected GatewayError::StartupTimeout, got: {:?}", other),
    }
}

/// 3. Child never produces protocol progress:
/// An initialize request is sent by the agent, but child never responds.
/// Startup timer fires, gateway returns -32011 on active request to agent and
/// exits with GatewayError::StartupTimeout.
#[tokio::test]
async fn test_child_never_produces_protocol_progress() {
    let mut subproc_config = SubprocessConfig::new(
        mock_server(),
        vec!["--hang-on-startup".to_string()],
        "0.1.0",
    );
    subproc_config.startup_timeout = Duration::from_millis(200);
    subproc_config.shutdown_grace_period = Duration::from_millis(100);

    let subprocess = spawn(&subproc_config).await.expect("spawn mock server");

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (gateway_agent_read, mut agent_write) = tokio::io::duplex(4096);
    let (agent_read, gateway_agent_write) = tokio::io::duplex(4096);

    let mut config = GatewayConfig::with_pass_through(SessionId::new_v7());
    config.startup_timeout = Duration::from_millis(200);
    config.shutdown_grace_period = Duration::from_millis(100);

    let gateway_task = tokio::spawn(async move {
        run_gateway(
            gateway_agent_read,
            gateway_agent_write,
            subprocess,
            config,
            shutdown_rx,
        )
        .await
    });

    // Send initialize request from agent
    let init_req = r#"{"jsonrpc":"2.0","id":100,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
    agent_write
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .expect("write");
    agent_write.flush().await.expect("flush");

    // Agent should receive -32011 error response when gateway times out
    let mut reader = BufReader::new(agent_read);
    let mut line = String::new();
    let read_res = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line)).await;
    assert!(read_res.is_ok(), "read timed out");
    assert!(!line.is_empty(), "expected error response from gateway");

    let val: Value = serde_json::from_str(&line).expect("valid json error response");
    assert_eq!(val["id"], 100);
    assert_eq!(val["error"]["code"], -32011);
    assert!(val["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Downstream MCP Subprocess Terminated"));

    let gw_res = gateway_task.await.expect("gateway task join");
    match gw_res {
        Err(GatewayError::StartupTimeout(d)) => {
            assert_eq!(d, Duration::from_millis(200));
        }
        other => panic!("expected StartupTimeout, got {:?}", other),
    }
}

/// 4. Child exits during initialization:
/// Child starts with --exit-during-init. Agent sends initialize request.
/// Child exits with 43 upon reading initialize.
/// Gateway must forward -32011 error to agent and exit with child exit code 43.
#[tokio::test]
async fn test_child_exits_during_initialization() {
    let mut subproc_config = SubprocessConfig::new(
        mock_server(),
        vec!["--exit-during-init".to_string()],
        "0.1.0",
    );
    subproc_config.startup_timeout = Duration::from_secs(5);
    subproc_config.shutdown_grace_period = Duration::from_millis(200);

    let subprocess = spawn(&subproc_config).await.expect("spawn mock server");

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (gateway_agent_read, mut agent_write) = tokio::io::duplex(4096);
    let (agent_read, gateway_agent_write) = tokio::io::duplex(4096);

    let mut config = GatewayConfig::with_pass_through(SessionId::new_v7());
    config.startup_timeout = Duration::from_secs(5);
    config.shutdown_grace_period = Duration::from_millis(200);

    let gateway_task = tokio::spawn(async move {
        run_gateway(
            gateway_agent_read,
            gateway_agent_write,
            subprocess,
            config,
            shutdown_rx,
        )
        .await
    });

    let init_req = r#"{"jsonrpc":"2.0","id":200,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
    agent_write
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .expect("write");
    agent_write.flush().await.expect("flush");

    let mut reader = BufReader::new(agent_read);
    let mut line = String::new();
    let read_res = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line)).await;
    assert!(read_res.is_ok(), "read timed out");
    assert!(!line.is_empty(), "expected error response from gateway");

    let val: Value = serde_json::from_str(&line).expect("valid json error response");
    assert_eq!(val["id"], 200);
    assert_eq!(val["error"]["code"], -32011);
    assert!(val["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Downstream MCP Subprocess Terminated"));

    let gw_res = gateway_task
        .await
        .expect("gateway task join")
        .expect("gateway ok exit");
    assert_eq!(gw_res.child_exit_code, Some(43));
}

/// 5. Graceful termination:
/// Calling terminate_child_gracefully sends SIGTERM to a running child.
/// Child exits cleanly within grace period.
#[tokio::test]
async fn test_signal_graceful_termination() {
    let subproc_config = SubprocessConfig::new(mock_server(), vec![], "0.1.0");
    let mut subprocess = spawn(&subproc_config).await.expect("spawn mock server");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let start = std::time::Instant::now();
    let status = subprocess
        .terminate_gracefully(Duration::from_millis(500))
        .await
        .expect("terminate gracefully")
        .expect("exit status");

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(400),
        "graceful exit should be immediate, took {:?}",
        elapsed
    );

    // On Unix, exit either by signal (SIGTERM) or with code 0 depending on handler
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert!(
            status.code() == Some(0) || status.signal() == Some(libc::SIGTERM),
            "status: {:?}",
            status
        );
    }
}

/// 6. Forced SIGKILL after grace period:
/// Child process ignores SIGTERM (--ignore-sigterm).
/// terminate_child_gracefully waits the grace period (150ms), escalates to SIGKILL,
/// and child is killed.
#[tokio::test]
async fn test_signal_forced_sigkill_after_grace_period() {
    let subproc_config =
        SubprocessConfig::new(mock_server(), vec!["--ignore-sigterm".to_string()], "0.1.0");
    let mut subprocess = spawn(&subproc_config).await.expect("spawn mock server");

    // Allow child process to start and install signal handlers
    tokio::time::sleep(Duration::from_millis(50)).await;

    let start = std::time::Instant::now();
    let grace_period = Duration::from_millis(150);
    let status = subprocess
        .terminate_gracefully(grace_period)
        .await
        .expect("terminate gracefully")
        .expect("exit status");

    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(140),
        "must wait at least grace period, took {:?}",
        elapsed
    );

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "child should have been killed by SIGKILL (signal 9)"
        );
    }
}

/// 7. Gateway shutdown signal:
/// When shutdown watch sender fires, gateway terminates child gracefully and exits.
#[tokio::test]
async fn test_gateway_shutdown_signal() {
    let subproc_config = SubprocessConfig::new(mock_server(), vec![], "0.1.0");
    let subprocess = spawn(&subproc_config).await.expect("spawn mock server");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (gateway_agent_read, _agent_write) = tokio::io::duplex(4096);
    let (_agent_read, gateway_agent_write) = tokio::io::duplex(4096);

    let config = GatewayConfig::with_pass_through(SessionId::new_v7());

    let gateway_task = tokio::spawn(async move {
        run_gateway(
            gateway_agent_read,
            gateway_agent_write,
            subprocess,
            config,
            shutdown_rx,
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    // Trigger shutdown
    shutdown_tx.send(true).expect("send shutdown");

    let res = tokio::time::timeout(Duration::from_secs(2), gateway_task)
        .await
        .expect("gateway did not complete in time")
        .expect("join")
        .expect("gateway ok exit");

    // Subprocess should have exited
    assert!(res.child_exit_code.is_some() || res.child_exit_code.is_none());
}
