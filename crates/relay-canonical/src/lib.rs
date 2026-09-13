//! RFC 8785 JSON Canonicalization Scheme (JCS) and domain normalizers for Relay.
//!
//! Establishes the single authoritative canonical security representation (`CanonicalAction`)
//! of an agent action for both Cedar policy authorization and execution dispatch.

pub mod action;
pub mod jcs;
pub mod json_checker;
pub mod resource;
pub mod schema;
pub mod tool_identity;

use std::path::PathBuf;

pub use action::{ActionCanonicalizer, CanonicalAction};
pub use jcs::{canonicalize_json_str, canonicalize_value, canonicalize_value_to_string};
pub use json_checker::{parse_json_bytes_strictly, parse_json_strictly, MAX_CANONICAL_BYTES};
pub use resource::{
    DefaultResourceResolver, FilesystemNormalizer, GitHubNormalizer, GitHubSubResource,
    NormalizedGitHubResource, NormalizedPath, NormalizedSql, SqlNormalizer, SqlOperation,
};
pub use schema::{compute_schema_digest, pin_tool_schema};
pub use tool_identity::{validate_tool_identity, ToolIdentity};

use relay_domain::{CanonicalizationError, Canonicalizer};

/// Default implementation of the domain `Canonicalizer` trait
#[derive(Debug, Default, Clone)]
pub struct DefaultCanonicalizer;

impl Canonicalizer for DefaultCanonicalizer {
    fn canonicalize_json(&self, raw: &serde_json::Value) -> Result<Vec<u8>, CanonicalizationError> {
        jcs::canonicalize_value(raw)
    }

    fn normalize_path(
        &self,
        raw_path: &str,
        base_dir: &str,
    ) -> Result<String, CanonicalizationError> {
        let normalizer = FilesystemNormalizer::new(PathBuf::from(base_dir), false);
        let normalized = normalizer.resolve_path(raw_path)?;
        Ok(normalized.canonical_path().to_string())
    }

    fn normalize_sql(&self, raw_sql: &str) -> Result<String, CanonicalizationError> {
        let normalized = SqlNormalizer::normalize(raw_sql)?;
        Ok(normalized.canonical_sql)
    }
}
