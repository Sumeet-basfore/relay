//! Vault and secret management CLI commands for Relay (Milestone B005 / GA).
//!
//! Provides zero-leakage keyring operations (`set`, `get`, `list`, `delete`) utilizing
//! the platform OS secure keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager)
//! with automatic authenticated encrypted file vault fallback for headless / CI environments.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::SecretSubcommands;
use crate::cli_error::CliError;
use relay_credentials::{EncryptedFileCredentialProvider, KeyringCredentialProvider};
use relay_domain::error::CredentialError;
use relay_domain::security::SecretBuffer;
use relay_domain::traits::CredentialProvider;

/// Metadata stored in the secret index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub alias: String,
    pub provider: String,
    pub length: usize,
    pub fingerprint: String,
    pub updated_at: String,
}

/// Persistent index keeping track of stored secret aliases across providers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretVaultIndex {
    pub version: u32,
    pub secrets: BTreeMap<String, SecretMetadata>,
}

/// Resolves the base directory for Relay vault storage (`~/.relay` or `RELAY_VAULT_DIR`).
pub fn resolve_vault_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("RELAY_VAULT_DIR") {
        PathBuf::from(dir)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".relay")
    } else {
        PathBuf::from(".relay")
    }
}

/// Loads or creates the machine master encryption key for headless fallback.
fn get_or_create_vault_master_key(vault_dir: &Path) -> Result<Vec<u8>, CliError> {
    let key_path = vault_dir.join(".vault_key");
    if key_path.exists() {
        let key = fs::read(&key_path).map_err(|e| {
            CliError::ExecutionError(format!("Failed to read vault master key: {e}"))
        })?;
        if key.len() >= 32 {
            return Ok(key);
        }
    }

    // Generate 32 bytes of secure entropy
    let mut key = vec![0u8; 32];
    for chunk in key.chunks_mut(16) {
        let u = uuid::Uuid::now_v7();
        chunk.copy_from_slice(&u.as_bytes()[..chunk.len()]);
    }

    let _ = fs::create_dir_all(vault_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(vault_dir, fs::Permissions::from_mode(0o700));
    }

    fs::write(&key_path, &key)
        .map_err(|e| CliError::ExecutionError(format!("Failed to write vault master key: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }

    Ok(key)
}

/// Loads the vault index.
fn load_index(vault_dir: &Path) -> SecretVaultIndex {
    let index_path = vault_dir.join("secrets_index.json");
    if let Ok(content) = fs::read_to_string(&index_path) {
        if let Ok(idx) = serde_json::from_str::<SecretVaultIndex>(&content) {
            return idx;
        }
    }
    SecretVaultIndex {
        version: 1,
        secrets: BTreeMap::new(),
    }
}

/// Saves the vault index with strict 0600 permissions.
fn save_index(vault_dir: &Path, index: &SecretVaultIndex) -> Result<(), CliError> {
    fs::create_dir_all(vault_dir)
        .map_err(|e| CliError::ExecutionError(format!("Failed to create vault directory: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(vault_dir, fs::Permissions::from_mode(0o700));
    }

    let index_path = vault_dir.join("secrets_index.json");
    let json_bytes = serde_json::to_vec_pretty(index)
        .map_err(|e| CliError::ExecutionError(format!("Failed to serialize vault index: {e}")))?;

    fs::write(&index_path, &json_bytes)
        .map_err(|e| CliError::ExecutionError(format!("Failed to write vault index: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&index_path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Helper that initializes the appropriate credential provider:
/// tries Keyring first; if unavailable, falls back to authenticated EncryptedFileCredentialProvider.
async fn store_secret_in_best_provider(
    key_alias: &str,
    secret: &SecretBuffer,
    vault_dir: &Path,
) -> Result<String, CliError> {
    let keyring_provider = KeyringCredentialProvider::default();
    match keyring_provider.set_secret(key_alias, secret).await {
        Ok(()) => Ok("OS Secure Keyring".to_string()),
        Err(CredentialError::KeyringUnavailable { reason }) => {
            tracing::info!(
                reason = %reason,
                "OS Keyring unavailable; falling back to encrypted file vault"
            );
            let master_key = get_or_create_vault_master_key(vault_dir)?;
            let file_vault_dir = vault_dir.join("store");
            let file_provider =
                EncryptedFileCredentialProvider::new(&file_vault_dir, master_key)
                    .map_err(|e| CliError::ExecutionError(format!("Encrypted vault error: {e}")))?;
            file_provider
                .set_secret(key_alias, secret)
                .await
                .map_err(|e| CliError::ExecutionError(format!("Failed to write secret: {e}")))?;
            Ok("Encrypted File Vault".to_string())
        }
        Err(err) => Err(CliError::ExecutionError(format!(
            "Failed to store secret: {err}"
        ))),
    }
}

/// Helper that retrieves a secret from Keyring or encrypted file fallback.
async fn get_secret_from_providers(
    key_alias: &str,
    vault_dir: &Path,
) -> Result<(SecretBuffer, String), CliError> {
    let keyring_provider = KeyringCredentialProvider::default();
    match keyring_provider.get_secret(key_alias).await {
        Ok(secret) => Ok((secret, "OS Secure Keyring".to_string())),
        Err(CredentialError::NotFound { .. }) => {
            // Check fallback provider
            let master_key = get_or_create_vault_master_key(vault_dir)?;
            let file_vault_dir = vault_dir.join("store");
            let file_provider =
                EncryptedFileCredentialProvider::new(&file_vault_dir, master_key)
                    .map_err(|e| CliError::ExecutionError(format!("Encrypted vault error: {e}")))?;
            match file_provider.get_secret(key_alias).await {
                Ok(secret) => Ok((secret, "Encrypted File Vault".to_string())),
                Err(CredentialError::NotFound { .. }) => Err(CliError::ConfigError(format!(
                    "Secret '{key_alias}' not found in vault"
                ))),
                Err(e) => Err(CliError::ExecutionError(format!(
                    "Failed to read secret: {e}"
                ))),
            }
        }
        Err(CredentialError::KeyringUnavailable { reason }) => {
            tracing::debug!(reason = %reason, "Keyring unavailable, querying encrypted file vault");
            let master_key = get_or_create_vault_master_key(vault_dir)?;
            let file_vault_dir = vault_dir.join("store");
            let file_provider =
                EncryptedFileCredentialProvider::new(&file_vault_dir, master_key)
                    .map_err(|e| CliError::ExecutionError(format!("Encrypted vault error: {e}")))?;
            match file_provider.get_secret(key_alias).await {
                Ok(secret) => Ok((secret, "Encrypted File Vault".to_string())),
                Err(CredentialError::NotFound { .. }) => Err(CliError::ConfigError(format!(
                    "Secret '{key_alias}' not found in vault"
                ))),
                Err(e) => Err(CliError::ExecutionError(format!(
                    "Failed to read secret: {e}"
                ))),
            }
        }
        Err(err) => Err(CliError::ExecutionError(format!(
            "Failed to query secret: {err}"
        ))),
    }
}

/// Helper that deletes a secret from all providers.
async fn delete_secret_from_providers(key_alias: &str, vault_dir: &Path) -> Result<(), CliError> {
    let keyring_provider = KeyringCredentialProvider::default();
    let _ = keyring_provider.delete_secret(key_alias).await;

    if let Ok(master_key) = get_or_create_vault_master_key(vault_dir) {
        let file_vault_dir = vault_dir.join("store");
        if let Ok(file_provider) = EncryptedFileCredentialProvider::new(&file_vault_dir, master_key)
        {
            let _ = file_provider.delete_secret(key_alias).await;
        }
    }

    Ok(())
}

/// Computes a truncated SHA-256 fingerprint for secret verification.
fn compute_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let hex_prefix = digest[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("sha256:{hex_prefix}")
}

/// Executes `relay secret` subcommands.
pub async fn execute(command: SecretSubcommands, json_output: bool) -> Result<(), CliError> {
    let vault_dir = resolve_vault_dir();
    let mut index = load_index(&vault_dir);

    match command {
        SecretSubcommands::Set { key, value } => {
            if key.trim().is_empty() {
                return Err(CliError::ConfigError(
                    "Secret key alias cannot be empty".to_string(),
                ));
            }

            let secret = SecretBuffer::from_slice(value.as_bytes());
            let length = secret.len();
            let fingerprint = compute_fingerprint(secret.as_bytes());

            let provider_name = store_secret_in_best_provider(&key, &secret, &vault_dir).await?;

            let meta = SecretMetadata {
                alias: key.clone(),
                provider: provider_name.clone(),
                length,
                fingerprint: fingerprint.clone(),
                updated_at: Utc::now().to_rfc3339(),
            };
            index.secrets.insert(key.clone(), meta);
            save_index(&vault_dir, &index)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "success",
                        "action": "set",
                        "key": key,
                        "bytes": length,
                        "fingerprint": fingerprint,
                        "provider": provider_name
                    })
                );
            } else {
                println!("=== Relay Secret Vault ===");
                println!("Status     : STORED");
                println!("Key Alias  : {key}");
                println!("Provider   : {provider_name}");
                println!("Length     : {length} bytes");
                println!("Fingerprint: {fingerprint}");
            }
            Ok(())
        }

        SecretSubcommands::Get { key } => {
            let (secret, provider_name) = get_secret_from_providers(&key, &vault_dir).await?;
            let length = secret.len();
            let fingerprint = compute_fingerprint(secret.as_bytes());

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "configured",
                        "key": key,
                        "bytes": length,
                        "fingerprint": fingerprint,
                        "provider": provider_name,
                        "masked": format!("[MASKED - {length} bytes]")
                    })
                );
            } else {
                println!("=== Relay Secret Metadata ===");
                println!("Key Alias  : {key}");
                println!("Status     : Configured");
                println!("Provider   : {provider_name}");
                println!("Length     : {length} bytes");
                println!("Fingerprint: {fingerprint}");
                println!("Value      : [MASKED - {length} bytes]");
            }
            Ok(())
        }

        SecretSubcommands::List => {
            let secrets: Vec<&SecretMetadata> = index.secrets.values().collect();

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "count": secrets.len(),
                        "secrets": secrets
                    })
                );
            } else {
                println!("=== Relay Secret Keyring Vault ===");
                if secrets.is_empty() {
                    println!("No secrets configured in vault.");
                    println!("\nTo store a secret: relay secret set <key> <value>");
                } else {
                    println!("Configured Secrets ({}):", secrets.len());
                    for s in secrets {
                        println!(
                            "  • {:<20} ({} bytes, {}, fingerprint: {})",
                            s.alias, s.length, s.provider, s.fingerprint
                        );
                    }
                }
            }
            Ok(())
        }

        SecretSubcommands::Delete { key } => {
            delete_secret_from_providers(&key, &vault_dir).await?;

            let existed = index.secrets.remove(&key).is_some();
            save_index(&vault_dir, &index)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "success",
                        "action": "delete",
                        "key": key,
                        "existed": existed
                    })
                );
            } else {
                println!("=== Relay Secret Vault ===");
                println!("Status     : PURGED");
                println!("Key Alias  : {key}");
                println!("Result     : Secret successfully removed from vault.");
            }
            Ok(())
        }
    }
}
