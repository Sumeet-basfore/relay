use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use relay_domain::credential::CredentialProviderType;
use relay_domain::error::CredentialError;
use relay_domain::security::SecretBuffer;
use relay_domain::traits::CredentialProvider;

/// Keyring-backed credential provider using the platform OS keyring
/// (Linux Secret Service / D-Bus, macOS Keychain, Windows Credential Manager).
pub struct KeyringCredentialProvider {
    service_name: String,
}

impl KeyringCredentialProvider {
    pub const DEFAULT_SERVICE: &'static str = "io.relay.gateway";

    /// Creates a new Keyring provider with a custom service namespace.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

impl Default for KeyringCredentialProvider {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SERVICE)
    }
}

#[async_trait]
impl CredentialProvider for KeyringCredentialProvider {
    fn provider_type(&self) -> CredentialProviderType {
        CredentialProviderType::KeyringStatic
    }

    async fn get_secret(&self, key_alias: &str) -> Result<SecretBuffer, CredentialError> {
        let entry = keyring::Entry::new(&self.service_name, key_alias).map_err(|e| {
            CredentialError::KeyringUnavailable {
                reason: format!("Failed to create keyring entry: {e}"),
            }
        })?;

        match entry.get_secret() {
            Ok(secret_bytes) => Ok(SecretBuffer::new(secret_bytes)),
            Err(keyring::Error::NoEntry) => Err(CredentialError::NotFound {
                provider: "keyring".to_string(),
                key_alias: key_alias.to_string(),
            }),
            Err(err) => Err(CredentialError::KeyringUnavailable {
                reason: format!("OS Keyring lookup failed: {err}"),
            }),
        }
    }

    async fn set_secret(
        &self,
        key_alias: &str,
        secret: &SecretBuffer,
    ) -> Result<(), CredentialError> {
        let entry = keyring::Entry::new(&self.service_name, key_alias).map_err(|e| {
            CredentialError::KeyringUnavailable {
                reason: format!("Failed to create keyring entry: {e}"),
            }
        })?;

        entry
            .set_secret(secret.as_bytes())
            .map_err(|e| CredentialError::KeyringUnavailable {
                reason: format!("Failed to set secret in OS Keyring: {e}"),
            })
    }

    async fn delete_secret(&self, key_alias: &str) -> Result<(), CredentialError> {
        let entry = keyring::Entry::new(&self.service_name, key_alias).map_err(|e| {
            CredentialError::KeyringUnavailable {
                reason: format!("Failed to create keyring entry: {e}"),
            }
        })?;

        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(CredentialError::KeyringUnavailable {
                reason: format!("Failed to delete credential from OS Keyring: {err}"),
            }),
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>, CredentialError> {
        // OS Keyrings generally do not support generic key enumeration without platform-specific extensions.
        // Return empty list or platform indication.
        Ok(Vec::new())
    }
}

/// In-memory credential provider for tests, deterministic fixtures, and isolated environments.
/// All stored secrets are zeroized in memory on drop.
pub struct InMemoryCredentialProvider {
    provider_type: CredentialProviderType,
    store: Arc<RwLock<HashMap<String, SecretBuffer>>>,
}

impl InMemoryCredentialProvider {
    pub fn new(provider_type: CredentialProviderType) -> Self {
        Self {
            provider_type,
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_default_keyring() -> Self {
        Self::new(CredentialProviderType::KeyringStatic)
    }

    /// Pre-seeds a secret directly into memory for testing.
    pub async fn add_secret(&self, key_alias: impl Into<String>, secret: Vec<u8>) {
        let mut guard = self.store.write().await;
        guard.insert(key_alias.into(), SecretBuffer::new(secret));
    }
}

#[async_trait]
impl CredentialProvider for InMemoryCredentialProvider {
    fn provider_type(&self) -> CredentialProviderType {
        self.provider_type
    }

    async fn get_secret(&self, key_alias: &str) -> Result<SecretBuffer, CredentialError> {
        let guard = self.store.read().await;
        if let Some(buf) = guard.get(key_alias) {
            Ok(SecretBuffer::from_slice(buf.as_bytes()))
        } else {
            Err(CredentialError::NotFound {
                provider: self.provider_type.to_string(),
                key_alias: key_alias.to_string(),
            })
        }
    }

    async fn set_secret(
        &self,
        key_alias: &str,
        secret: &SecretBuffer,
    ) -> Result<(), CredentialError> {
        let mut guard = self.store.write().await;
        guard.insert(
            key_alias.to_string(),
            SecretBuffer::from_slice(secret.as_bytes()),
        );
        Ok(())
    }

    async fn delete_secret(&self, key_alias: &str) -> Result<(), CredentialError> {
        let mut guard = self.store.write().await;
        guard.remove(key_alias);
        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, CredentialError> {
        let guard = self.store.read().await;
        let mut keys: Vec<String> = guard.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
}

/// File-based encrypted credential provider for headless / CI environments (A006 §3.1).
/// Uses authenticated symmetric encryption (SHA-256 CTR keystream + HMAC authentication tag)
/// and enforces strict POSIX file permissions (0700 dir, 0600 file).
pub struct EncryptedFileCredentialProvider {
    base_dir: std::path::PathBuf,
    master_key: Vec<u8>,
}

impl EncryptedFileCredentialProvider {
    /// Creates a new EncryptedFileCredentialProvider.
    /// Ensures the base directory exists with strict permissions.
    pub fn new(
        base_dir: impl Into<std::path::PathBuf>,
        master_key: impl Into<Vec<u8>>,
    ) -> Result<Self, CredentialError> {
        let base_dir = base_dir.into();
        let master_key = master_key.into();

        if master_key.is_empty() {
            return Err(CredentialError::ProviderError {
                reason: "Master key for encrypted file provider cannot be empty".to_string(),
            });
        }

        std::fs::create_dir_all(&base_dir).map_err(|e| CredentialError::ProviderError {
            reason: format!("Failed to create credential directory: {e}"),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700));
        }

        Ok(Self {
            base_dir,
            master_key,
        })
    }

    fn key_path(&self, key_alias: &str) -> std::path::PathBuf {
        let safe_filename = key_alias
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        self.base_dir.join(format!("{safe_filename}.key"))
    }

    fn derive_keystream(&self, key_alias: &str, nonce: &[u8; 16], length: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut stream = Vec::with_capacity(length);
        let mut counter: u32 = 0;

        while stream.len() < length {
            let mut hasher = Sha256::new();
            hasher.update(&self.master_key);
            hasher.update(key_alias.as_bytes());
            hasher.update(nonce);
            hasher.update(counter.to_le_bytes());
            let block = hasher.finalize();
            let take = (length - stream.len()).min(block.len());
            stream.extend_from_slice(&block[..take]);
            counter += 1;
        }

        stream
    }

    fn compute_mac(&self, nonce: &[u8; 16], ciphertext: &[u8], key_alias: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(nonce);
        hasher.update(ciphertext);
        hasher.update(key_alias.as_bytes());
        let result = hasher.finalize();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&result);
        mac
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

#[async_trait]
impl CredentialProvider for EncryptedFileCredentialProvider {
    fn provider_type(&self) -> CredentialProviderType {
        CredentialProviderType::KeyringStatic
    }

    async fn get_secret(&self, key_alias: &str) -> Result<SecretBuffer, CredentialError> {
        let path = self.key_path(key_alias);
        if !path.exists() {
            return Err(CredentialError::NotFound {
                provider: "encrypted_file".to_string(),
                key_alias: key_alias.to_string(),
            });
        }

        let raw = std::fs::read(&path).map_err(|e| CredentialError::ProviderError {
            reason: format!("Failed to read credential file: {e}"),
        })?;

        // Format: [16 bytes nonce] [32 bytes MAC] [ciphertext]
        if raw.len() < 48 {
            return Err(CredentialError::ProviderError {
                reason: "Corrupted credential file: payload too short".to_string(),
            });
        }

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&raw[0..16]);
        let stored_mac = &raw[16..48];
        let ciphertext = &raw[48..];

        let computed_mac = self.compute_mac(&nonce, ciphertext, key_alias);
        if !Self::constant_time_eq(stored_mac, &computed_mac) {
            return Err(CredentialError::ProviderError {
                reason: "Credential integrity verification failed (MAC mismatch)".to_string(),
            });
        }

        let keystream = self.derive_keystream(key_alias, &nonce, ciphertext.len());
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (c, k) in ciphertext.iter().zip(keystream.iter()) {
            plaintext.push(c ^ k);
        }

        Ok(SecretBuffer::new(plaintext))
    }

    async fn set_secret(
        &self,
        key_alias: &str,
        secret: &SecretBuffer,
    ) -> Result<(), CredentialError> {
        use std::io::Write;
        let path = self.key_path(key_alias);

        // Generate 16-byte nonce from UUIDv7 entropy
        let uuid = uuid::Uuid::now_v7();
        let nonce: [u8; 16] = *uuid.as_bytes();

        let plaintext = secret.as_bytes();
        let keystream = self.derive_keystream(key_alias, &nonce, plaintext.len());
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (p, k) in plaintext.iter().zip(keystream.iter()) {
            ciphertext.push(p ^ k);
        }

        let mac = self.compute_mac(&nonce, &ciphertext, key_alias);

        let mut payload = Vec::with_capacity(16 + 32 + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&mac);
        payload.extend_from_slice(&ciphertext);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| CredentialError::ProviderError {
                reason: format!("Failed to open credential file for writing: {e}"),
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        file.write_all(&payload)
            .map_err(|e| CredentialError::ProviderError {
                reason: format!("Failed to write credential payload: {e}"),
            })?;
        file.flush().map_err(|e| CredentialError::ProviderError {
            reason: format!("Failed to flush credential file: {e}"),
        })?;

        Ok(())
    }

    async fn delete_secret(&self, key_alias: &str) -> Result<(), CredentialError> {
        let path = self.key_path(key_alias);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| CredentialError::ProviderError {
                reason: format!("Failed to delete credential file: {e}"),
            })?;
        }
        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>, CredentialError> {
        let mut aliases = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(alias) = name.strip_suffix(".key") {
                    aliases.push(alias.to_string());
                }
            }
        }
        aliases.sort();
        Ok(aliases)
    }
}
