use relay_domain::security::{RedactedSecret, SecretBuffer};

#[test]
fn test_secret_buffer_display_and_debug_redaction() {
    let secret = SecretBuffer::new(b"SUPER_SECRET_GITHUB_TOKEN_12345".to_vec());

    // Display must redact
    let display_str = format!("{}", secret);
    assert_eq!(display_str, "[REDACTED SECRET]");
    assert!(!display_str.contains("SUPER_SECRET"));

    // Debug must redact
    let debug_str = format!("{:?}", secret);
    assert_eq!(debug_str, "SecretBuffer([REDACTED 31 bytes])");
    assert!(!debug_str.contains("SUPER_SECRET"));

    // Expose secret via explicit method
    assert_eq!(secret.as_bytes(), b"SUPER_SECRET_GITHUB_TOKEN_12345");
    assert_eq!(secret.as_str(), Some("SUPER_SECRET_GITHUB_TOKEN_12345"));
}

#[test]
fn test_redacted_secret_string() {
    let secret = RedactedSecret::new("my-api-key-xyz".to_string());

    let display_str = format!("{}", secret);
    assert_eq!(display_str, "[REDACTED]");
    assert!(!display_str.contains("xyz"));

    let debug_str = format!("{:?}", secret);
    assert_eq!(debug_str, "RedactedSecret([REDACTED])");

    assert_eq!(secret.expose(), "my-api-key-xyz");
}

use std::str::FromStr;

#[test]
fn test_secret_buffer_from_slice_and_from_str() {
    let secret = SecretBuffer::from_slice(b"temp_secret");
    assert_eq!(secret.as_bytes(), b"temp_secret");
    assert_eq!(secret.len(), 11);
    assert!(!secret.is_empty());

    let from_str = SecretBuffer::from_str("temp_secret_str").expect("Infallible");
    assert_eq!(from_str.as_bytes(), b"temp_secret_str");
}
