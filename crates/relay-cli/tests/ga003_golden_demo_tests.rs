//! GA003 Golden Reference Deployment & Public Demo Integration Tests
//!
//! Validates the complete reproducible end-to-end golden deployment scenarios:
//! - Authorized native filesystem reads (Cedar ALLOW)
//! - Unauthorized sensitive asset reads (Cedar DENY fail-closed)
//! - Scoped filesystem writes (Cedar ALLOW)
//! - Step-up approval enforcement (Cedar REQUIRE_APPROVAL)
//! - Subprocess credential isolation (0 ambient secrets)
//! - Anti-SSRF cloud metadata blocking (SI-022)
//! - DSSE action receipt and SQLite ledger chain verification
//! - Fail-closed detection of disk/ledger tampering

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Stdio};
use tempfile::tempdir;

struct TestMcpClient {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

impl TestMcpClient {
    fn spawn(relay_bin: &std::path::Path, cwd: &std::path::Path) -> Self {
        let mut cmd = std::process::Command::new(relay_bin);
        cmd.arg("--config")
            .arg("relay.toml")
            .arg("run")
            .arg("--non-interactive")
            .arg("--")
            .arg("python3")
            .arg("server.py")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn relay run");
        let stdout = child.stdout.take().expect("stdout pipe");
        let reader = BufReader::new(stdout);

        let mut client = Self { child, reader };

        // Handshake: initialize
        client.send_request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ga003-ci-agent", "version": "0.1.0"}
            }),
            100,
        );
        let _init_resp = client.read_response();

        // Notification: initialized
        client.send_notification("notifications/initialized", serde_json::json!({}));

        client
    }

    fn send_request(&mut self, method: &str, params: serde_json::Value, id: u64) {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        let mut line = payload.to_string();
        line.push('\n');
        let stdin = self.child.stdin.as_mut().expect("stdin pipe");
        stdin.write_all(line.as_bytes()).expect("write to stdin");
        stdin.flush().expect("flush stdin");
    }

    fn send_notification(&mut self, method: &str, params: serde_json::Value) {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        let mut line = payload.to_string();
        line.push('\n');
        let stdin = self.child.stdin.as_mut().expect("stdin pipe");
        stdin.write_all(line.as_bytes()).expect("write to stdin");
        stdin.flush().expect("flush stdin");
    }

    fn read_response(&mut self) -> serde_json::Value {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read line");
        serde_json::from_str(&line).unwrap_or_else(|_| serde_json::json!({"raw": line}))
    }

    fn call_tool(&mut self, name: &str, args: serde_json::Value, id: u64) -> serde_json::Value {
        self.send_request(
            "tools/call",
            serde_json::json!({
                "name": name,
                "arguments": args
            }),
            id,
        );
        self.read_response()
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_ga003_golden_reference_lifecycle() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let temp_dir = tempdir().unwrap();
    let workspace = temp_dir.path();

    // 1. Create directory layout
    let policies_dir = workspace.join("policies");
    let fixtures_dir = workspace.join("fixtures");
    let output_dir = fixtures_dir.join("output");
    let relay_dir = workspace.join(".relay");

    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::create_dir_all(&output_dir).unwrap();
    std::fs::create_dir_all(&relay_dir).unwrap();

    // 2. Copy policies, schema, fixtures, and server.py
    std::fs::copy(
        repo_root.join("demo/policies/demo.cedar"),
        policies_dir.join("demo.cedar"),
    )
    .unwrap();
    std::fs::copy(
        repo_root.join("demo/policies/relay_schema.cedarschema"),
        policies_dir.join("relay_schema.cedarschema"),
    )
    .unwrap();
    std::fs::copy(
        repo_root.join("demo/fixtures/public.txt"),
        fixtures_dir.join("public.txt"),
    )
    .unwrap();
    std::fs::copy(
        repo_root.join("demo/fixtures/protected.txt"),
        fixtures_dir.join("protected.txt"),
    )
    .unwrap();
    std::fs::copy(
        repo_root.join("demo/adversarial-mcp/server.py"),
        workspace.join("server.py"),
    )
    .unwrap();

    // 3. Write relay.toml
    let toml_content = r#"
[security]
default_deny = true
approval_timeout_secs = 30
max_frame_size_bytes = 4194304

[policy]
policy_dir = "policies"

[storage]
ledger_path = ".relay/ledger.db"

[proxy]
bind_host = "127.0.0.1"
port = 0
"#;
    std::fs::write(workspace.join("relay.toml"), toml_content).unwrap();

    let relay_bin = assert_cmd::cargo::cargo_bin("relay");

    // 4. Verify relay doctor passes
    let mut doc_cmd = Command::cargo_bin("relay").unwrap();
    doc_cmd
        .arg("--config")
        .arg("relay.toml")
        .arg("doctor")
        .current_dir(workspace)
        .assert()
        .success();

    // 5. Spawn Governed MCP Client
    let mut client = TestMcpClient::spawn(&relay_bin, workspace);

    // Scene 1: Permitted Read
    let pub_path = fixtures_dir
        .join("public.txt")
        .to_str()
        .unwrap()
        .to_string();
    let resp1 = client.call_tool("fs.read_file", serde_json::json!({"path": pub_path}), 1);
    assert!(resp1.get("result").is_some());
    assert!(!resp1["result"]
        .get("isError")
        .unwrap_or(&serde_json::Value::Bool(false))
        .as_bool()
        .unwrap_or(false));

    // Scene 2: Unauthorized Read (DENY)
    let prot_path = fixtures_dir
        .join("protected.txt")
        .to_str()
        .unwrap()
        .to_string();
    let resp2 = client.call_tool("fs.read_file", serde_json::json!({"path": prot_path}), 2);
    assert!(
        resp2.get("error").is_some(),
        "Expected error for protected.txt read"
    );

    // Scene 3: Scoped Write (ALLOW)
    let out_file = output_dir
        .join("test_out.txt")
        .to_str()
        .unwrap()
        .to_string();
    let resp3 = client.call_tool(
        "fs.write_file",
        serde_json::json!({
            "path": out_file,
            "content": "Golden CI test payload"
        }),
        3,
    );
    assert!(resp3.get("result").is_some());

    // Scene 4: Approval Step-Up (DENY / Non-interactive fail-closed)
    let resp4 = client.call_tool("fs.delete_file", serde_json::json!({"path": out_file}), 4);
    assert!(resp4.get("error").is_some());

    // Scene 5: Adversarial Probes
    let resp_cred = client.call_tool("attack_exfiltrate_credentials", serde_json::json!({}), 5);
    let cred_text = resp_cred["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        cred_text.contains("Zero ambient credentials"),
        "Unexpected credential leak"
    );

    let resp_ssrf = client.call_tool("attack_probe_cloud_metadata", serde_json::json!({}), 6);
    let ssrf_text = resp_ssrf["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        ssrf_text.contains("ATTACK BLOCKED"),
        "Cloud metadata access was not blocked"
    );

    client.stop();

    // 6. Verify Ledger
    let ledger_path = workspace.join(".relay/ledger.db");
    let mut verify_cmd = Command::cargo_bin("relay").unwrap();
    verify_cmd
        .arg("--config")
        .arg("relay.toml")
        .arg("verify")
        .current_dir(workspace)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // 7. Test Ledger Tamper Detection
    let tampered_db = workspace.join(".relay/tampered.db");
    std::fs::copy(&ledger_path, &tampered_db).unwrap();
    let mut db_bytes = std::fs::read(&tampered_db).unwrap();
    if db_bytes.len() > 4096 {
        db_bytes[4000] ^= 0xFF;
    } else {
        let idx = db_bytes.len().saturating_sub(1);
        db_bytes[idx] ^= 0xFF;
    }
    std::fs::write(&tampered_db, db_bytes).unwrap();

    let mut verify_tamper = Command::cargo_bin("relay").unwrap();
    verify_tamper
        .arg("verify")
        .arg("--ledger")
        .arg(&tampered_db)
        .current_dir(workspace)
        .assert()
        .failure();
}
