//! Cryptographically signed offline license entitlement module.
//!
//! Enforces:
//! 1. Ed25519 digital signature verification over canonicalized claims.
//! 2. Zero network phone-home requirement (100% offline verification).
//! 3. Tamper-evident claims validation.
//! 4. Hybrid revocation: 30-day short-lived licenses + emergency signed CRL.
//! 5. Non-interference invariant: License state never grants execution authority
//!    nor bypasses Cedar policies ("Payment status is not authorization status").

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntitlementError {
    #[error("Failed to canonicalize claims: {0}")]
    Canonicalization(String),
    #[error("Invalid signature encoding: {0}")]
    InvalidSignatureEncoding(String),
    #[error("Cryptographic signature verification failed: invalid signature")]
    InvalidSignature,
    #[error("License expired on {expires_at}, grace period of {grace_days} days has lapsed")]
    LicenseExpired { expires_at: i64, grace_days: u32 },
    #[error("License {license_id} has been revoked via CRL {crl_id}")]
    LicenseRevoked { license_id: String, crl_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    Community,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseClaims {
    pub license_id: String,
    pub customer_id: String,
    pub customer_name: String,
    pub tier: LicenseTier,
    pub seat_count: u32,
    pub issued_at: i64,
    pub expires_at: i64,
    pub grace_period_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    Active { seconds_remaining: i64 },
    GracePeriod { seconds_remaining_in_grace: i64 },
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCertificate {
    pub claims: LicenseClaims,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationListClaims {
    pub crl_id: String,
    pub issued_at: i64,
    pub revoked_license_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    pub claims: RevocationListClaims,
    pub signature: String,
}

impl CertificateRevocationList {
    /// Issues a signed Certificate Revocation List (CRL).
    pub fn issue(
        claims: RevocationListClaims,
        signing_key: &SigningKey,
    ) -> Result<Self, EntitlementError> {
        let canonical_bytes = serde_jcs::to_vec(&claims)
            .map_err(|e| EntitlementError::Canonicalization(e.to_string()))?;
        let signature = signing_key.sign(&canonical_bytes);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        Ok(Self {
            claims,
            signature: signature_b64,
        })
    }

    /// Verifies the digital signature on the CRL against a trusted public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), EntitlementError> {
        let canonical_bytes = serde_jcs::to_vec(&self.claims)
            .map_err(|e| EntitlementError::Canonicalization(e.to_string()))?;

        let sig_bytes = BASE64
            .decode(&self.signature)
            .map_err(|e| EntitlementError::InvalidSignatureEncoding(e.to_string()))?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| EntitlementError::InvalidSignatureEncoding(e.to_string()))?;

        verifying_key
            .verify(&canonical_bytes, &signature)
            .map_err(|_| EntitlementError::InvalidSignature)?;

        Ok(())
    }

    /// Checks whether a license ID is in this revocation list.
    pub fn is_revoked(&self, license_id: &str) -> bool {
        self.claims
            .revoked_license_ids
            .iter()
            .any(|id| id == license_id)
    }
}

impl LicenseCertificate {
    /// Signs license claims using an Ed25519 private signing key to issue a license certificate.
    pub fn issue(
        claims: LicenseClaims,
        signing_key: &SigningKey,
    ) -> Result<Self, EntitlementError> {
        let canonical_bytes = serde_jcs::to_vec(&claims)
            .map_err(|e| EntitlementError::Canonicalization(e.to_string()))?;
        let signature = signing_key.sign(&canonical_bytes);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        Ok(Self {
            claims,
            signature: signature_b64,
        })
    }

    /// Verifies the digital signature and validity of the license against a trusted public key.
    ///
    /// This function operates completely offline with zero network connections.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        current_time_unix: i64,
    ) -> Result<LicenseStatus, EntitlementError> {
        self.verify_with_crl(verifying_key, current_time_unix, None)
    }

    /// Verifies the digital signature and validity of the license against a trusted public key
    /// and an optional signed Certificate Revocation List (CRL).
    pub fn verify_with_crl(
        &self,
        verifying_key: &VerifyingKey,
        current_time_unix: i64,
        crl: Option<&CertificateRevocationList>,
    ) -> Result<LicenseStatus, EntitlementError> {
        // 1. Verify digital signature over canonicalized claims
        let canonical_bytes = serde_jcs::to_vec(&self.claims)
            .map_err(|e| EntitlementError::Canonicalization(e.to_string()))?;

        let sig_bytes = BASE64
            .decode(&self.signature)
            .map_err(|e| EntitlementError::InvalidSignatureEncoding(e.to_string()))?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| EntitlementError::InvalidSignatureEncoding(e.to_string()))?;

        verifying_key
            .verify(&canonical_bytes, &signature)
            .map_err(|_| EntitlementError::InvalidSignature)?;

        // 2. Check Certificate Revocation List (CRL) if provided
        if let Some(revocation_list) = crl {
            revocation_list.verify(verifying_key)?;
            if revocation_list.is_revoked(&self.claims.license_id) {
                return Err(EntitlementError::LicenseRevoked {
                    license_id: self.claims.license_id.clone(),
                    crl_id: revocation_list.claims.crl_id.clone(),
                });
            }
        }

        // 3. Evaluate time boundaries
        let grace_period_seconds = (self.claims.grace_period_days as i64) * 86_400;
        let hard_expiry = self.claims.expires_at + grace_period_seconds;

        if current_time_unix < self.claims.expires_at {
            Ok(LicenseStatus::Active {
                seconds_remaining: self.claims.expires_at - current_time_unix,
            })
        } else if current_time_unix <= hard_expiry {
            Ok(LicenseStatus::GracePeriod {
                seconds_remaining_in_grace: hard_expiry - current_time_unix,
            })
        } else {
            Err(EntitlementError::LicenseExpired {
                expires_at: self.claims.expires_at,
                grace_days: self.claims.grace_period_days,
            })
        }
    }
}
