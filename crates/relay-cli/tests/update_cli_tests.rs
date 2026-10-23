use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_update_help() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args(["update", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Check for and install updates to Relay",
        ))
        .stdout(predicate::str::contains("--check"))
        .stdout(predicate::str::contains("--version"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--from-file"))
        .stdout(predicate::str::contains("--binary-path"));
}

#[test]
fn test_upgrade_alias_help() {
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args(["upgrade", "--help"]);
    cmd.assert().success().stdout(predicate::str::contains(
        "Check for and install updates to Relay",
    ));
}

#[test]
fn test_update_from_file_local_package() {
    let tmp = tempdir().expect("temp dir");
    let dest_bin = tmp.path().join("installed_relay_bin");
    let archive_path = tmp.path().join("relay-v0.2.0-mock.tar.gz");

    // Create a mock executable script inside a tar.gz archive
    let mut tar_builder = tar::Builder::new(Vec::new());

    #[cfg(unix)]
    let script_content = b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"relay 0.2.0\"; exit 0; fi\necho \"running relay 0.2.0\"\nexit 0\n";
    #[cfg(windows)]
    let script_content =
        b"@echo off\nif \"%1\"==\"--version\" (echo relay 0.2.0 & exit /b 0)\nexit /b 0\n";

    let mut header = tar::Header::new_gnu();
    header.set_size(script_content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();

    let bin_name = if cfg!(windows) { "relay.exe" } else { "relay" };
    tar_builder
        .append_data(&mut header, bin_name, &script_content[..])
        .unwrap();
    let uncompressed_tar = tar_builder.into_inner().unwrap();

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &uncompressed_tar).unwrap();
    let tar_gz_bytes = encoder.finish().unwrap();

    std::fs::write(&archive_path, tar_gz_bytes).expect("Failed to write mock archive");

    // Execute relay update --from-file
    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args([
        "update",
        "--from-file",
        archive_path.to_str().unwrap(),
        "--binary-path",
        dest_bin.to_str().unwrap(),
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Relay Local Package Update"))
        .stdout(predicate::str::contains("Successfully installed Relay"));

    assert!(dest_bin.exists(), "Target binary was not installed");
}

#[test]
fn test_update_from_file_json_output() {
    let tmp = tempdir().expect("temp dir");
    let dest_bin = tmp.path().join("installed_relay_json");
    let archive_path = tmp.path().join("relay-v0.2.0-json.tar.gz");

    let mut tar_builder = tar::Builder::new(Vec::new());

    #[cfg(unix)]
    let script_content = b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"relay 0.2.0\"; exit 0; fi\nexit 0\n";
    #[cfg(windows)]
    let script_content =
        b"@echo off\nif \"%1\"==\"--version\" (echo relay 0.2.0 & exit /b 0)\nexit /b 0\n";

    let mut header = tar::Header::new_gnu();
    header.set_size(script_content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();

    let bin_name = if cfg!(windows) { "relay.exe" } else { "relay" };
    tar_builder
        .append_data(&mut header, bin_name, &script_content[..])
        .unwrap();
    let uncompressed_tar = tar_builder.into_inner().unwrap();

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &uncompressed_tar).unwrap();
    let tar_gz_bytes = encoder.finish().unwrap();

    std::fs::write(&archive_path, tar_gz_bytes).expect("Failed to write mock archive");

    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args([
        "--json",
        "update",
        "--from-file",
        archive_path.to_str().unwrap(),
        "--binary-path",
        dest_bin.to_str().unwrap(),
    ]);

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("Valid JSON");
    assert_eq!(json["status"], "success");
    assert_eq!(json["mode"], "local_archive");
    assert_eq!(json["installed_path"], dest_bin.to_str().unwrap());
}

#[tokio::test]
async fn test_update_check_with_mock_github_api() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let mock_release = serde_json::json!({
        "tag_name": "v0.9.0",
        "name": "Relay Release v0.9.0",
        "html_url": "https://github.com/Sumeet-basfore/relay/releases/tag/v0.9.0",
        "published_at": "2026-10-23T00:00:00Z",
        "body": "Major security enhancements and automated updater",
        "assets": []
    });

    Mock::given(method("GET"))
        .and(path("/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_release))
        .mount(&mock_server)
        .await;

    let release_url = format!("{}/releases/latest", mock_server.uri());

    let mut cmd = Command::cargo_bin("relay").expect("Binary relay should exist");
    cmd.args(["--json", "update", "--check", "--release-url", &release_url]);

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("Valid JSON");
    assert_eq!(json["update_available"], true);
    assert_eq!(json["latest_version"], "0.9.0");
    assert_eq!(json["tag_name"], "v0.9.0");
}
