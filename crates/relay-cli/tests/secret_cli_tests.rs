use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_secret_help() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args(["secret", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Manage vaulted credentials in the OS secure keyring",
        ))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("delete"));
}

#[test]
fn test_secret_full_lifecycle_isolation_and_no_leakage() {
    let tmp = tempdir().expect("temp dir");
    let secret_val = "ghp_super_confidential_token_9876543210";

    // 1. Initial list should be empty
    let mut cmd_list_empty = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_list_empty
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "list"]);
    cmd_list_empty
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets configured in vault."));

    // 2. Set secret
    let mut cmd_set = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_set
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "set", "github_token", secret_val]);
    let assert_set = cmd_set.assert().success();

    // Verify plaintext secret was NEVER leaked in stdout or stderr
    let stdout_set = String::from_utf8_lossy(&assert_set.get_output().stdout);
    let stderr_set = String::from_utf8_lossy(&assert_set.get_output().stderr);
    assert!(
        !stdout_set.contains(secret_val),
        "stdout leaked secret value during set!"
    );
    assert!(
        !stderr_set.contains(secret_val),
        "stderr leaked secret value during set!"
    );
    assert!(stdout_set.contains("github_token"));
    assert!(stdout_set.contains("STORED"));

    // 3. Get secret metadata (should display masked value and length, NEVER raw secret)
    let mut cmd_get = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_get
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "get", "github_token"]);
    let assert_get = cmd_get.assert().success();

    let stdout_get = String::from_utf8_lossy(&assert_get.get_output().stdout);
    let stderr_get = String::from_utf8_lossy(&assert_get.get_output().stderr);
    assert!(
        !stdout_get.contains(secret_val),
        "stdout leaked secret value during get!"
    );
    assert!(
        !stderr_get.contains(secret_val),
        "stderr leaked secret value during get!"
    );
    assert!(stdout_get.contains("Status     : Configured"));
    assert!(stdout_get.contains("Length     : 39 bytes"));
    assert!(stdout_get.contains("[MASKED - 39 bytes]"));

    // 4. List secrets (should list alias)
    let mut cmd_list = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_list
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "list"]);
    cmd_list
        .assert()
        .success()
        .stdout(predicate::str::contains("Configured Secrets (1):"))
        .stdout(predicate::str::contains("github_token"))
        .stdout(predicate::str::contains("39 bytes"));

    // 5. Delete secret
    let mut cmd_del = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_del
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "delete", "github_token"]);
    cmd_del
        .assert()
        .success()
        .stdout(predicate::str::contains("PURGED"))
        .stdout(predicate::str::contains("github_token"));

    // 6. Get deleted secret should fail with not found
    let mut cmd_get_deleted = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_get_deleted
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "get", "github_token"]);
    cmd_get_deleted
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found in vault"));
}

#[test]
fn test_secret_json_output() {
    let tmp = tempdir().expect("temp dir");

    // Set with JSON
    let mut cmd_set = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_set.env("RELAY_VAULT_DIR", tmp.path()).args([
        "secret",
        "set",
        "pg_pass",
        "super_pass_123",
        "--json",
    ]);
    cmd_set
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"success\""))
        .stdout(predicate::str::contains("\"key\":\"pg_pass\""))
        .stdout(predicate::str::contains("\"bytes\":14"));

    // Get with JSON
    let mut cmd_get = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_get
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "get", "pg_pass", "--json"]);
    cmd_get
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"configured\""))
        .stdout(predicate::str::contains("\"key\":\"pg_pass\""))
        .stdout(predicate::str::contains("\"bytes\":14"))
        .stdout(predicate::str::contains(
            "\"masked\":\"[MASKED - 14 bytes]\"",
        ));

    // List with JSON
    let mut cmd_list = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_list
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "list", "--json"]);
    cmd_list
        .assert()
        .success()
        .stdout(predicate::str::contains("\"count\":1"))
        .stdout(predicate::str::contains("\"alias\":\"pg_pass\""));

    // Delete with JSON
    let mut cmd_del = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd_del
        .env("RELAY_VAULT_DIR", tmp.path())
        .args(["secret", "delete", "pg_pass", "--json"]);
    cmd_del
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"success\""))
        .stdout(predicate::str::contains("\"action\":\"delete\""))
        .stdout(predicate::str::contains("\"key\":\"pg_pass\""));
}
