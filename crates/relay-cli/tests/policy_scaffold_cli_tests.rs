use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn mock_server_path() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin("mock-mcp-server")
}

#[test]
fn test_scaffold_help() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args(["policy", "scaffold", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Auto-scaffold Cedar security policies",
        ))
        .stdout(predicate::str::contains("--from-json"))
        .stdout(predicate::str::contains("--dry-run"))
        .stdout(predicate::str::contains("--force"));
}

#[test]
fn test_scaffold_dry_run_from_json() {
    let tmp = tempdir().expect("temp dir");
    let json_file = tmp.path().join("tools.json");
    fs::write(
        &json_file,
        r#"[
            {"name": "fetch_file", "description": "Read file contents", "inputSchema": {"type": "object"}},
            {"name": "write_report", "description": "Save report to disk", "inputSchema": {"type": "object"}},
            {"name": "execute_bash", "description": "Run shell command", "inputSchema": {"type": "object"}}
        ]"#,
    )
    .expect("write json");

    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args([
        "policy",
        "scaffold",
        "--from-json",
        json_file.to_str().unwrap(),
        "--dry-run",
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Dry Run"))
        .stdout(predicate::str::contains("--- schema.cedarschema ---"))
        .stdout(predicate::str::contains("--- policy.cedar ---"))
        .stdout(predicate::str::contains("~/.ssh"))
        .stdout(predicate::str::contains("~/.aws"))
        .stdout(predicate::str::contains(".env"))
        .stdout(predicate::str::contains("/etc/shadow"))
        .stdout(predicate::str::contains("fetch_file"))
        .stdout(predicate::str::contains("write_report"))
        .stdout(predicate::str::contains("execute_bash"))
        .stdout(predicate::str::contains("Read-Only    : 1 (Permitted)"))
        .stdout(predicate::str::contains(
            "Mutation     : 1 (Approval Required)",
        ))
        .stdout(predicate::str::contains(
            "Destructive  : 1 (Approval Required)",
        ));
}

#[test]
fn test_scaffold_writes_files_and_validates_with_policy_engine() {
    let tmp = tempdir().expect("temp dir");
    let json_file = tmp.path().join("tools.json");
    let out_dir = tmp.path().join("policies");

    fs::write(
        &json_file,
        r#"[
            {"name": "get_weather", "description": "Get current weather", "inputSchema": {"type": "object"}},
            {"name": "post_tweet", "description": "Publish a tweet", "inputSchema": {"type": "object"}},
            {"name": "rm_rf", "description": "Delete all files", "inputSchema": {"type": "object"}}
        ]"#,
    )
    .expect("write json");

    // Scaffold into out_dir
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args([
        "policy",
        "scaffold",
        "--from-json",
        json_file.to_str().unwrap(),
        "--output",
        out_dir.to_str().unwrap(),
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Status           : SUCCESS"))
        .stdout(predicate::str::contains("Pre-Flight Check : PASSED"));

    assert!(out_dir.join("policy.cedar").exists());
    assert!(out_dir.join("schema.cedarschema").exists());

    // Re-running without --force should fail
    let mut cmd_fail = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_fail.args([
        "policy",
        "scaffold",
        "--from-json",
        json_file.to_str().unwrap(),
        "--output",
        out_dir.to_str().unwrap(),
    ]);
    cmd_fail
        .assert()
        .failure()
        .stderr(predicate::str::contains("already contains"));

    // Re-running with --force should succeed
    let mut cmd_force = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_force.args([
        "policy",
        "scaffold",
        "--from-json",
        json_file.to_str().unwrap(),
        "--output",
        out_dir.to_str().unwrap(),
        "--force",
    ]);
    cmd_force.assert().success();

    // Now validate the generated policy directory with `relay policy validate --path`
    let mut validate_cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    validate_cmd.args([
        "policy",
        "validate",
        "--path",
        out_dir.join("policy.cedar").to_str().unwrap(),
    ]);
    validate_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "VALID (Passed Strict Schema Conformity)",
        ))
        .stdout(predicate::str::contains("Policy Count  : 7"));
}

#[test]
fn test_scaffold_live_subprocess_discovery() {
    let mock_server = mock_server_path();
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args(["policy", "scaffold", "--dry-run", "--"]);
    cmd.arg(mock_server);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("echo"))
        .stdout(predicate::str::contains("relay.internal.env_dump"));
}
