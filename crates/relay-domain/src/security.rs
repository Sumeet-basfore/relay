use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use zeroize::Zeroize;

use crate::error::CredentialError;
use crate::id::LeaseId;

/// Locks heap memory using libc::mlock to prevent secret material from being swapped to disk.
fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    // SAFETY: ptr is guaranteed non-null and valid for len bytes from the active Vec allocation.
    let res = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if res == 0 {
        true
    } else {
        let errno = std::io::Error::last_os_error();
        tracing::debug!(
            errno = %errno,
            "libc::mlock failed (likely RLIMIT_MEMLOCK reached or unprivileged); continuing with memory zeroization only"
        );
        false
    }
}

/// Unlocks memory previously locked with libc::mlock.
fn unlock_memory(ptr: *const u8, len: usize) {
    if len > 0 {
        // SAFETY: ptr is valid for len bytes prior to deallocation.
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }
}

/// Protected in-memory container for sensitive cryptographic credentials.
/// Implements virtual memory locking (`mlock`), auto-zeroization on drop,
/// and masks `Debug` / `Display` to prevent secret leaks.
///
/// NOTE: This type intentionally does NOT derive or implement `Clone`, `Serialize`, or `Deserialize`.
pub struct SecretBuffer {
    inner: Vec<u8>,
    is_locked: bool,
}

impl SecretBuffer {
    /// Creates a new `SecretBuffer` from raw bytes and attempts to lock it in RAM.
    pub fn new(secret: Vec<u8>) -> Self {
        let is_locked = lock_memory(secret.as_ptr(), secret.len());
        Self {
            inner: secret,
            is_locked,
        }
    }

    /// Creates a new `SecretBuffer` from a byte slice.
    pub fn from_slice(secret: &[u8]) -> Self {
        Self::new(secret.to_vec())
    }

    /// Exposes raw secret bytes exclusively for authorized dispatch.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Converts secret bytes to a UTF-8 string slice if valid.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.inner).ok()
    }

    /// Returns the length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Checks if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Checks whether memory locking (`mlock`) succeeded for this buffer.
    pub fn is_memory_locked(&self) -> bool {
        self.is_locked
    }

    /// Exposes secret bytes strictly within a transient closure to minimize exposure.
    pub fn expose_scoped<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.inner)
    }
}

impl Zeroize for SecretBuffer {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        // 1. Overwrite secret bytes with zeroes in RAM
        self.inner.zeroize();

        // 2. Unlock memory if it was successfully locked
        if self.is_locked {
            unlock_memory(self.inner.as_ptr(), self.inner.len());
            self.is_locked = false;
        }
    }
}

impl std::str::FromStr for SecretBuffer {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.as_bytes().to_vec()))
    }
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer([REDACTED {} bytes])", self.inner.len())
    }
}

impl fmt::Display for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED SECRET]")
    }
}

/// RAII Lease Guard (A003 §5.1).
/// Enforces single-scope access, checks expiration, and zeroizes memory on Drop.
/// MUST NEVER implement: Debug (with raw secrets), Display (with raw secrets), Serialize, Deserialize, Clone.
pub struct CredentialLeaseGuard {
    lease_id: LeaseId,
    secret: SecretBuffer,
    expires_at: DateTime<Utc>,
}

impl CredentialLeaseGuard {
    pub fn new(lease_id: LeaseId, secret: SecretBuffer, expires_at: DateTime<Utc>) -> Self {
        Self {
            lease_id,
            secret,
            expires_at,
        }
    }

    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_memory_locked(&self) -> bool {
        self.secret.is_memory_locked()
    }

    /// Access the secret as a UTF-8 string within a scoped closure.
    pub fn use_secret<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R, CredentialError> {
        if self.is_expired() {
            return Err(CredentialError::LeaseExpired {
                lease_id: self.lease_id.to_string(),
            });
        }
        let s = self
            .secret
            .as_str()
            .ok_or_else(|| CredentialError::ProviderError {
                reason: "Secret is not valid UTF-8 string".to_string(),
            })?;
        Ok(f(s))
    }

    /// Access the raw secret bytes within a scoped closure.
    pub fn use_secret_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, CredentialError> {
        if self.is_expired() {
            return Err(CredentialError::LeaseExpired {
                lease_id: self.lease_id.to_string(),
            });
        }
        Ok(self.secret.expose_scoped(f))
    }
}

impl fmt::Debug for CredentialLeaseGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CredentialLeaseGuard([REDACTED LEASE {}])",
            self.lease_id
        )
    }
}

impl fmt::Display for CredentialLeaseGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED LEASE GUARD]")
    }
}

/// Redacted string wrapper for secret identifiers/tokens
#[derive(Clone)]
pub struct RedactedSecret(SecretString);

impl RedactedSecret {
    pub fn new(secret: String) -> Self {
        Self(SecretString::new(secret))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedSecret([REDACTED])")
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}
