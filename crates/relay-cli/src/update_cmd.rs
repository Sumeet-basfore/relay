use crate::cli::UpdateArgs;
use crate::cli_error::CliError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const DEFAULT_REPO: &str = "Sumeet-basfore/relay";

#[derive(Debug, Deserialize, Serialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub name: Option<String>,
    pub html_url: String,
    pub published_at: Option<String>,
    pub body: Option<String>,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

/// Detects the target triple for the current operating system and CPU architecture.
pub fn detect_target() -> Result<&'static str, CliError> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let target = match (arch, os) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        _ => {
            return Err(CliError::ExecutionError(format!(
                "Unsupported architecture and operating system: {arch}-{os}"
            )))
        }
    };
    Ok(target)
}

/// Compares semver version strings to determine if candidate is newer than current.
pub fn is_newer_version(current: &str, candidate: &str) -> bool {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let clean = s.trim_start_matches('v');
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() >= 3 {
            Some((
                parts[0].parse().ok()?,
                parts[1].parse().ok()?,
                parts[2]
                    .split('-')
                    .next()?
                    .split('+')
                    .next()?
                    .parse()
                    .ok()?,
            ))
        } else if parts.len() == 2 {
            Some((parts[0].parse().ok()?, parts[1].parse().ok()?, 0))
        } else if parts.len() == 1 {
            Some((parts[0].parse().ok()?, 0, 0))
        } else {
            None
        }
    };

    match (parse(current), parse(candidate)) {
        (Some(c), Some(cand)) => cand > c,
        _ => current.trim_start_matches('v') != candidate.trim_start_matches('v'),
    }
}

/// Verifies that the SHA-256 checksum of the archive matches the expected manifest.
pub fn verify_checksum(
    archive_bytes: &[u8],
    manifest: &str,
    archive_name: &str,
) -> Result<(), CliError> {
    let mut hasher = Sha256::new();
    hasher.update(archive_bytes);
    let computed_hex = hex::encode(hasher.finalize());

    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let expected_hex = parts[0];
            let file_entry = parts[1].trim_start_matches('*');
            if file_entry == archive_name || file_entry.ends_with(archive_name) {
                if !computed_hex.eq_ignore_ascii_case(expected_hex) {
                    return Err(CliError::SecurityFailure(format!(
                        "Cryptographic checksum mismatch for {archive_name}! Expected {expected_hex}, computed {computed_hex}"
                    )));
                }
                return Ok(());
            }
        }
    }

    // If manifest contains checksums but no entry matched
    Err(CliError::SecurityFailure(format!(
        "Archive {archive_name} was not found in release checksums.sha256 manifest"
    )))
}

/// Resolves the destination path where the relay binary should be installed.
pub fn resolve_destination_path(custom: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(p) = custom {
        return Ok(p.to_path_buf());
    }

    if let Ok(current_exe) = std::env::current_exe() {
        let path_str = current_exe.to_string_lossy();
        // If running in development (cargo target dir) or /tmp, prefer ~/.local/bin/relay
        if path_str.contains("/target/") || path_str.starts_with("/tmp") {
            if let Some(home) = std::env::var_os("HOME") {
                let local_bin = PathBuf::from(home).join(".local/bin/relay");
                return Ok(local_bin);
            }
        }
        return Ok(current_exe);
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local/bin/relay"));
    }

    Err(CliError::ExecutionError(
        "Could not determine installation path. Please specify --binary-path <PATH>".into(),
    ))
}

/// Extracts a tar.gz archive and installs the binary to dest_path atomically.
pub fn extract_and_install(archive_bytes: &[u8], dest_path: &Path) -> Result<(), CliError> {
    let gz = flate2::read::GzDecoder::new(archive_bytes);
    let mut tar = tar::Archive::new(gz);

    let tmp_dir = tempfile::Builder::new()
        .prefix("relay-update-")
        .tempdir()
        .map_err(|e| {
            CliError::ExecutionError(format!("Failed to create temporary directory: {e}"))
        })?;

    tar.unpack(tmp_dir.path())
        .map_err(|e| CliError::ExecutionError(format!("Failed to unpack release archive: {e}")))?;

    // Locate binary in unpacked contents
    let bin_name = if cfg!(windows) { "relay.exe" } else { "relay" };

    fn find_bin(dir: &Path, bin_name: &str) -> Option<PathBuf> {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && p.file_name().is_some_and(|n| n == bin_name) {
                    return Some(p);
                } else if p.is_dir() {
                    if let Some(res) = find_bin(&p, bin_name) {
                        return Some(res);
                    }
                }
            }
        }
        None
    }

    let extracted_bin = find_bin(tmp_dir.path(), bin_name).ok_or_else(|| {
        CliError::ExecutionError(format!(
            "Binary '{bin_name}' not found inside downloaded release archive"
        ))
    })?;

    // On Unix, ensure executable bit is set
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&extracted_bin, perms);
    }

    // Pre-flight check: verify binary can execute cleanly
    let verify_run = std::process::Command::new(&extracted_bin)
        .arg("--version")
        .output();

    match verify_run {
        Ok(out) if out.status.success() => {
            tracing::info!("Pre-flight verification passed for extracted binary");
        }
        Ok(out) => {
            return Err(CliError::SecurityFailure(format!(
                "Pre-flight verification failed: binary exited with code {:?}",
                out.status.code()
            )));
        }
        Err(err) => {
            return Err(CliError::SecurityFailure(format!(
                "Pre-flight verification failed: unable to execute extracted binary: {err}"
            )));
        }
    }

    // Atomic install / replacement
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CliError::ExecutionError(format!(
                "Failed to create target directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let temp_dest = dest_path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::copy(&extracted_bin, &temp_dest).map_err(|e| {
        CliError::ExecutionError(format!(
            "Failed to stage binary at {}: {e}",
            temp_dest.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_dest, std::fs::Permissions::from_mode(0o755));
    }

    // Atomic rename
    #[cfg(unix)]
    {
        std::fs::rename(&temp_dest, dest_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_dest);
            CliError::ExecutionError(format!(
                "Failed to replace existing binary at {}: {e}. (Try running with elevated privileges or use --binary-path)",
                dest_path.display()
            ))
        })?;
    }

    #[cfg(windows)]
    {
        let old_backup = dest_path.with_extension("old");
        if dest_path.exists() {
            let _ = std::fs::rename(dest_path, &old_backup);
        }
        std::fs::rename(&temp_dest, dest_path).map_err(|e| {
            CliError::ExecutionError(format!(
                "Failed to replace binary at {}: {e}",
                dest_path.display()
            ))
        })?;
        if old_backup.exists() {
            let _ = std::fs::remove_file(&old_backup);
        }
    }

    Ok(())
}

/// Executes the `relay update` command workflow.
pub async fn execute(args: UpdateArgs, json_output: bool) -> Result<(), CliError> {
    let current_version = env!("CARGO_PKG_VERSION");
    let target = detect_target()?;

    // 1. Offline / local archive installation
    if let Some(ref file_path) = args.from_file {
        if !file_path.exists() {
            return Err(CliError::ExecutionError(format!(
                "Specified archive file does not exist: {}",
                file_path.display()
            )));
        }

        let archive_bytes = std::fs::read(file_path).map_err(|e| {
            CliError::ExecutionError(format!(
                "Failed to read archive {}: {e}",
                file_path.display()
            ))
        })?;

        let dest_path = resolve_destination_path(args.binary_path.as_deref())?;

        if !json_output {
            println!("=== Relay Local Package Update ===");
            println!("Archive:      {}", file_path.display());
            println!("Destination:  {}", dest_path.display());
            println!("Target:       {target}");
        }

        extract_and_install(&archive_bytes, &dest_path)?;

        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "status": "success",
                    "mode": "local_archive",
                    "archive": file_path.display().to_string(),
                    "installed_path": dest_path.display().to_string(),
                    "target": target
                })
            );
        } else {
            println!(
                "Successfully installed Relay from local package to {}",
                dest_path.display()
            );
        }
        return Ok(());
    }

    // 2. Online GitHub Release Query
    let client = reqwest::Client::builder()
        .user_agent(format!("relay-updater/{current_version}"))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| CliError::ExecutionError(format!("Failed to initialize HTTP client: {e}")))?;

    let release_url = match args.release_url.as_deref() {
        Some(url) => url.to_string(),
        None => {
            if args.version == "latest" {
                format!("https://api.github.com/repos/{DEFAULT_REPO}/releases/latest")
            } else {
                let tag = if args.version.starts_with('v') {
                    args.version.clone()
                } else {
                    format!("v{}", args.version)
                };
                format!("https://api.github.com/repos/{DEFAULT_REPO}/releases/tags/{tag}")
            }
        }
    };

    if !json_output && !args.check {
        println!("Checking for updates from {release_url}...");
    }

    let resp = client.get(&release_url).send().await.map_err(|e| {
        CliError::ExecutionError(format!(
            "Failed to reach GitHub release API at {release_url}: {e}. (Check internet connection or use --from-file for offline install)"
        ))
    })?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(CliError::ExecutionError(format!(
            "Release '{}' was not found on GitHub repository {DEFAULT_REPO}",
            args.version
        )));
    }

    if !resp.status().is_success() {
        return Err(CliError::ExecutionError(format!(
            "GitHub release API returned error HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        )));
    }

    let release: GitHubRelease = resp.json().await.map_err(|e| {
        CliError::ExecutionError(format!("Failed to parse GitHub release metadata JSON: {e}"))
    })?;

    let latest_version = release.tag_name.trim_start_matches('v');
    let has_update = is_newer_version(current_version, latest_version);

    if args.check {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "tag_name": release.tag_name,
                    "target": target,
                    "update_available": has_update,
                    "html_url": release.html_url,
                    "published_at": release.published_at,
                    "body": release.body
                })
            );
        } else {
            println!("=== Relay Version Check ===");
            println!("Current Version  : v{current_version}");
            println!(
                "Latest Release   : v{latest_version} ({})",
                release.tag_name
            );
            println!("Target Platform  : {target}");
            if has_update {
                println!("Status           : UPDATE AVAILABLE");
                println!("Release URL      : {}", release.html_url);
                if let Some(notes) = release.body.as_ref() {
                    let first_line = notes.lines().next().unwrap_or("");
                    if !first_line.is_empty() {
                        println!("Notes            : {first_line}");
                    }
                }
                println!("\nRun 'relay update' to download and install this update.");
            } else {
                println!("Status           : UP TO DATE (You are running the latest version)");
            }
        }
        return Ok(());
    }

    if !has_update && !args.force {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "status": "up_to_date",
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "target": target,
                    "update_available": false
                })
            );
        } else {
            println!("Relay is already up to date (v{current_version}).");
            println!("Use 'relay update --force' to reinstall or force-update.");
        }
        return Ok(());
    }

    // 3. Locate Target Assets
    let expected_tarball = format!("relay-v{latest_version}-{target}.tar.gz");
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == expected_tarball)
        .ok_or_else(|| {
            CliError::ExecutionError(format!(
                "Release {} does not have pre-built binary asset for platform '{target}' (expected: {expected_tarball})",
                release.tag_name
            ))
        })?;

    let checksum_asset = release
        .assets
        .iter()
        .find(|a| a.name == "checksums.sha256" || a.name == "SHA256SUMS");

    let dest_path = resolve_destination_path(args.binary_path.as_deref())?;

    if !json_output {
        println!("=== Installing Relay Update ===");
        println!("Upgrading:    v{current_version} -> v{latest_version}");
        println!("Platform:     {target}");
        println!("Package:      {}", asset.name);
        println!("Destination:  {}", dest_path.display());
        println!("Downloading package ({} bytes)...", asset.size);
    }

    // Download archive
    let archive_resp = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .map_err(|e| {
            CliError::ExecutionError(format!(
                "Failed to download release asset {}: {e}",
                asset.name
            ))
        })?;

    if !archive_resp.status().is_success() {
        return Err(CliError::ExecutionError(format!(
            "Failed to download asset {}: HTTP {}",
            asset.name,
            archive_resp.status()
        )));
    }

    let archive_bytes = archive_resp.bytes().await.map_err(|e| {
        CliError::ExecutionError(format!("Failed to read asset payload {}: {e}", asset.name))
    })?;

    // Download and verify checksum
    if let Some(cs_asset) = checksum_asset {
        if !json_output {
            println!("Verifying cryptographic SHA-256 checksum...");
        }
        let cs_resp = client
            .get(&cs_asset.browser_download_url)
            .send()
            .await
            .map_err(|e| {
                CliError::ExecutionError(format!("Failed to download checksum manifest: {e}"))
            })?;

        if cs_resp.status().is_success() {
            let manifest = cs_resp.text().await.unwrap_or_default();
            verify_checksum(&archive_bytes, &manifest, &asset.name)?;
            if !json_output {
                println!("Checksum verification: PASSED (SHA-256 match)");
            }
        }
    } else if !json_output {
        println!("Notice: No checksums.sha256 manifest present in release assets; proceeding with HTTPS transport verification.");
    }

    // Extract and atomically replace binary
    extract_and_install(&archive_bytes, &dest_path)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "status": "success",
                "previous_version": current_version,
                "installed_version": latest_version,
                "destination": dest_path.display().to_string(),
                "target": target
            })
        );
    } else {
        println!("\n=== Relay Update Complete ===");
        println!("Successfully updated Relay to v{latest_version}!");
        println!("Binary location: {}", dest_path.display());
        println!("Run 'relay doctor' to verify system health.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_target_returns_supported_triple() {
        let target = detect_target();
        assert!(target.is_ok());
        let t = target.unwrap();
        assert!(t.contains("linux") || t.contains("darwin") || t.contains("windows"));
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.1.0", "0.1.1"));
        assert!(is_newer_version("0.1.0", "0.2.0"));
        assert!(is_newer_version("0.1.0", "1.0.0"));
        assert!(is_newer_version("v0.1.0", "v0.1.1"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.2.0", "0.1.9"));
        assert!(!is_newer_version("1.0.0", "0.9.9"));
    }

    #[test]
    fn test_verify_checksum_success() {
        let content = b"hello relay updater test";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected_hash = hex::encode(hasher.finalize());

        let manifest = format!("{expected_hash}  relay-v0.1.1-x86_64-unknown-linux-gnu.tar.gz\n");
        let result = verify_checksum(
            content,
            &manifest,
            "relay-v0.1.1-x86_64-unknown-linux-gnu.tar.gz",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksum_mismatch() {
        let content = b"hello relay updater test";
        let manifest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  relay-v0.1.1-x86_64-unknown-linux-gnu.tar.gz\n";
        let result = verify_checksum(
            content,
            manifest,
            "relay-v0.1.1-x86_64-unknown-linux-gnu.tar.gz",
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch"));
    }

    #[test]
    fn test_verify_checksum_missing_file_in_manifest() {
        let content = b"hello relay updater test";
        let manifest =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  other-file.tar.gz\n";
        let result = verify_checksum(
            content,
            manifest,
            "relay-v0.1.1-x86_64-unknown-linux-gnu.tar.gz",
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("was not found in release checksums"));
    }

    #[test]
    fn test_extract_and_install_from_tar_gz() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_bin = temp_dir.path().join("installed_relay");

        // Construct in-memory tar.gz with a mock executable script
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

        let res = extract_and_install(&tar_gz_bytes, &dest_bin);
        assert!(res.is_ok(), "Extraction failed: {:?}", res.err());
        assert!(dest_bin.exists());
    }
}
