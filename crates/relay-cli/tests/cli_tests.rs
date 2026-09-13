use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;

fn mock_server_path() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin("mock-mcp-server")
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Relay"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("policy"))
        .stdout(predicate::str::contains("secret"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("receipt"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("relay"));
}

#[test]
fn test_cli_doctor() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.arg("doctor");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Relay System Health & Foundation Diagnostics",
        ))
        .stdout(predicate::str::contains("Target Architecture"))
        .stdout(predicate::str::contains("Target OS"))
        .stdout(predicate::str::contains(
            "MCP Gateway Milestone B002 Operational",
        ));
}

#[test]
fn test_gateway_initialize_roundtrip() {
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("relay"))
        .args(["run", "--", mock_server_path().to_str().expect("path")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    let mut stdin = child.stdin.take().expect("stdin");
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    stdin
        .write_all(format!("{}\n", request).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");

    let line = read_line_with_timeout(&mut child, Duration::from_secs(5)).expect("response line");

    assert!(line.starts_with('{'));
    assert!(line.contains("mock-mcp-server"));
    assert!(!line.contains("Launching Relay"));

    let _ = child.kill();
}

#[test]
fn test_gateway_stdout_is_protocol_only() {
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("relay"))
        .args(["run", "--", mock_server_path().to_str().expect("path")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    let mut stdin = child.stdin.take().expect("stdin");
    let request = r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#;
    stdin
        .write_all(format!("{}\n", request).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");

    let line = read_line_with_timeout(&mut child, Duration::from_secs(5)).expect("response");

    assert!(line.starts_with('{') && line.ends_with('}'));
    assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok());

    let _ = child.kill();
}

#[test]
fn test_gateway_env_isolation() {
    std::env::set_var("RELAY_TEST_SECRET_ENV", "super-secret-value");

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("relay"))
        .args(["run", "--", mock_server_path().to_str().expect("path")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    let mut stdin = child.stdin.take().expect("stdin");

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    stdin
        .write_all(format!("{}\n", init).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");
    let _ = read_line_with_timeout(&mut child, Duration::from_secs(5));

    let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"relay.internal.env_dump","arguments":{}}}"#;
    stdin
        .write_all(format!("{}\n", call).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");

    let line =
        read_line_with_timeout(&mut child, Duration::from_secs(5)).expect("env dump response");

    assert!(!line.contains("RELAY_TEST_SECRET_ENV"));
    assert!(line.contains("RELAY_ACTIVE"));

    std::env::remove_var("RELAY_TEST_SECRET_ENV");
    let _ = child.kill();
}

fn read_line_with_timeout(child: &mut std::process::Child, timeout: Duration) -> Option<String> {
    use std::io::{BufReader, Read};

    let stdout = child.stdout.as_mut()?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let mut chunk = [0u8; 1];
        match reader.read(&mut chunk) {
            Ok(0) => return None,
            Ok(_) => {
                if chunk[0] == b'\n' {
                    return Some(line);
                }
                line.push(chunk[0] as char);
            }
            Err(_) => return None,
        }
    }
    None
}

#[test]
fn test_cli_sigterm_shutdown() {
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("relay"))
        .args(["run", "--", mock_server_path().to_str().expect("path")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    let mut stdin = child.stdin.take().expect("stdin");
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    stdin
        .write_all(format!("{}\n", request).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");

    let line = read_line_with_timeout(&mut child, Duration::from_secs(5)).expect("response line");
    assert!(line.contains("mock-mcp-server"));

    // Send SIGTERM to relay process
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }

    let start = std::time::Instant::now();
    let mut exited = false;
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        exited,
        "relay process did not terminate on SIGTERM within 5s"
    );
}

#[test]
fn test_cli_sigint_shutdown() {
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("relay"))
        .args(["run", "--", mock_server_path().to_str().expect("path")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    let mut stdin = child.stdin.take().expect("stdin");
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    stdin
        .write_all(format!("{}\n", request).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");

    let line = read_line_with_timeout(&mut child, Duration::from_secs(5)).expect("response line");
    assert!(line.contains("mock-mcp-server"));

    // Send SIGINT to relay process
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    let start = std::time::Instant::now();
    let mut exited = false;
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        exited,
        "relay process did not terminate on SIGINT within 5s"
    );
}

#[test]
fn test_cli_secret_regression_in_logs_and_errors() {
    let secret_env_key = "TEST_SECRET_KEY_ENV_XYZ";
    let secret_env_val = "SECRET_TOKEN_VALUE_ABC_987654";
    let secret_cli_arg = "--secret-token=SUPER_CONFIDENTIAL_123456";

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("relay"))
        .env(secret_env_key, secret_env_val)
        .args([
            "run",
            "--",
            mock_server_path().to_str().expect("path"),
            secret_cli_arg,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay");

    let mut stdin = child.stdin.take().expect("stdin");
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}"#;
    stdin
        .write_all(format!("{}\n", request).as_bytes())
        .expect("write");
    stdin.flush().expect("flush");

    let _ = read_line_with_timeout(&mut child, Duration::from_secs(5));

    // Send malformed input to trigger error paths
    stdin
        .write_all(b"INVALID RAW CORRUPTED FRAME\n")
        .expect("write malformed");
    stdin.flush().expect("flush");

    let _ = read_line_with_timeout(&mut child, Duration::from_secs(5));

    // Trigger shutdown via EOF
    drop(stdin);

    let output = child.wait_with_output().expect("wait with output");
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    // Assert sensitive args and env vars never appear in stdout or stderr
    assert!(
        !stdout_str.contains("SUPER_CONFIDENTIAL_123456"),
        "stdout leaked secret CLI arg: {}",
        stdout_str
    );
    assert!(
        !stderr_str.contains("SUPER_CONFIDENTIAL_123456"),
        "stderr leaked secret CLI arg: {}",
        stderr_str
    );
    assert!(
        !stdout_str.contains("SECRET_TOKEN_VALUE_ABC_987654"),
        "stdout leaked secret env value: {}",
        stdout_str
    );
    assert!(
        !stderr_str.contains("SECRET_TOKEN_VALUE_ABC_987654"),
        "stderr leaked secret env value: {}",
        stderr_str
    );
}
