//! Stripe billing webhook signature verification and payload processing.
//!
//! Enforces:
//! 1. HMAC-SHA256 signature verification (`Stripe-Signature: t=...,v1=...`).
//! 2. Constant-time equality check to prevent timing side-channel attacks.
//! 3. Strict timestamp replay protection ($|t_{\text{now}} - t_{\text{req}}| \le 300\text{s}$).
//! 4. Unconditional rejection of untrusted client-side payment indicators.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("Missing or malformed Stripe-Signature header")]
    MalformedHeader,
    #[error("Missing timestamp 't' or signature 'v1' in signature header")]
    MissingSignatureComponents,
    #[error("Webhook timestamp outside tolerance window ({skew_seconds}s > {tolerance_seconds}s)")]
    TimestampOutOfTolerance {
        skew_seconds: i64,
        tolerance_seconds: i64,
    },
    #[error("Cryptographic HMAC-SHA256 signature mismatch")]
    InvalidSignature,
    #[error("Failed to parse JSON webhook payload: {0}")]
    JsonParse(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: serde_json::Value,
}

pub struct StripeWebhookVerifier;

impl StripeWebhookVerifier {
    /// Verifies a Stripe webhook payload against the webhook signing secret and tolerance window.
    pub fn verify(
        raw_payload: &[u8],
        sig_header: &str,
        secret: &str,
        now_unix: i64,
        tolerance_seconds: i64,
    ) -> Result<StripeEvent, WebhookError> {
        // 1. Parse t=... and v1=... from header
        let mut timestamp: Option<i64> = None;
        let mut signatures: Vec<&str> = Vec::new();

        for part in sig_header.split(',') {
            let part = part.trim();
            if let Some(t_str) = part.strip_prefix("t=") {
                if let Ok(t) = t_str.parse::<i64>() {
                    timestamp = Some(t);
                }
            } else if let Some(v1_str) = part.strip_prefix("v1=") {
                signatures.push(v1_str);
            }
        }

        let t = timestamp.ok_or(WebhookError::MissingSignatureComponents)?;
        if signatures.is_empty() {
            return Err(WebhookError::MissingSignatureComponents);
        }

        // 2. Replay tolerance check
        let skew = (now_unix - t).abs();
        if skew > tolerance_seconds {
            return Err(WebhookError::TimestampOutOfTolerance {
                skew_seconds: skew,
                tolerance_seconds,
            });
        }

        // 3. Compute expected HMAC-SHA256 over t.payload
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| WebhookError::InvalidSignature)?;

        mac.update(t.to_string().as_bytes());
        mac.update(b".");
        mac.update(raw_payload);

        let expected_tag = mac.finalize().into_bytes();

        // 4. Verify against provided v1 signatures using constant-time check
        let mut signature_valid = false;
        for sig_hex in signatures {
            if let Ok(sig_bytes) = hex::decode(sig_hex) {
                if constant_time_eq(&sig_bytes, &expected_tag) {
                    signature_valid = true;
                    break;
                }
            }
        }

        if !signature_valid {
            return Err(WebhookError::InvalidSignature);
        }

        // 5. Parse deserialized payload
        let event: StripeEvent = serde_json::from_slice(raw_payload)
            .map_err(|e| WebhookError::JsonParse(e.to_string()))?;

        Ok(event)
    }

    /// Evaluates whether an execution claim comes from untrusted client assertions.
    ///
    /// Never trust `?payment_success=true` query parameters from the browser.
    pub fn is_untrusted_client_claim(url_query_or_param: &str) -> bool {
        let lower = url_query_or_param.to_lowercase();
        lower.contains("payment_success=true")
            || lower.contains("status=paid")
            || lower.contains("licensed=true")
    }
}

/// Constant-time comparison between two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
