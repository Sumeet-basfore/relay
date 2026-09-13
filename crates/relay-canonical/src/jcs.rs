//! RFC 8785 JSON Canonicalization Scheme (JCS) support.
//!
//! Provides deterministic canonicalization of arbitrary JSON values, guaranteeing:
//! - Predictable key ordering (UTF-16 code units / lexicographical sorting)
//! - Whitespace elimination outside string literals
//! - ECMAScript / RFC 8785 standard number formatting
//! - Standardized string escaping rules

use relay_domain::CanonicalizationError;
use serde_json::Value;

/// Canonicalizes a `serde_json::Value` into RFC 8785 canonical bytes.
pub fn canonicalize_value(val: &Value) -> Result<Vec<u8>, CanonicalizationError> {
    serde_jcs::to_vec(val).map_err(|e| CanonicalizationError::JcsError(e.to_string()))
}

/// Canonicalizes a `serde_json::Value` into an RFC 8785 canonical UTF-8 string.
pub fn canonicalize_value_to_string(val: &Value) -> Result<String, CanonicalizationError> {
    serde_jcs::to_string(val).map_err(|e| CanonicalizationError::JcsError(e.to_string()))
}

/// Parses a JSON string strictly (rejecting duplicate keys) and returns its RFC 8785 canonical bytes.
pub fn canonicalize_json_str(raw: &str) -> Result<Vec<u8>, CanonicalizationError> {
    let val = crate::json_checker::parse_json_strictly(raw)?;
    canonicalize_value(&val)
}
