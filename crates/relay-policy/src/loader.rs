//! Cedar Policy Loader and Validator.
//!
//! Loads, validates against Cedar schema, and computes cryptographic PolicySetDigest (SI-010).

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use relay_domain::{Digest, PolicyError};
use std::path::Path;
use std::str::FromStr;

/// Default Cedar policies bundled with Relay.
pub const RELAY_DEFAULT_POLICIES: &str = include_str!("../../../policies/default.cedar");

/// Policy loader and validator enforcing schema conformity and cryptographic digest binding.
pub struct PolicyLoader;

impl PolicyLoader {
    /// Computes the cryptographic SHA-256 hash of the policy string.
    pub fn compute_policy_digest(policy_text: &str) -> Digest {
        Digest::compute(policy_text.as_bytes())
    }

    /// Loads and strictly validates a policy set from a raw string.
    pub fn load_from_str(
        policy_src: &str,
        schema: &Schema,
    ) -> Result<(PolicySet, Digest), PolicyError> {
        let policy_set = PolicySet::from_str(policy_src)
            .map_err(|e| PolicyError::InitializationFailed(format!("Policy parse error: {e}")))?;

        let validator = Validator::new(schema.clone());
        let validation_res = validator.validate(&policy_set, ValidationMode::Strict);

        if !validation_res.validation_passed() {
            let error_msgs: Vec<String> = validation_res
                .validation_errors()
                .map(|e| e.to_string())
                .collect();
            return Err(PolicyError::SchemaError(format!(
                "Policy validation failed against schema: {}",
                error_msgs.join("; ")
            )));
        }

        for warning in validation_res.validation_warnings() {
            tracing::warn!(warning = %warning, "Cedar policy validation warning");
        }

        let digest = Self::compute_policy_digest(policy_src);
        Ok((policy_set, digest))
    }

    /// Loads policies from a specific `.cedar` file.
    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
        schema: &Schema,
    ) -> Result<(PolicySet, Digest), PolicyError> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref).map_err(|e| {
            PolicyError::InitializationFailed(format!(
                "Failed to read policy file '{}': {}",
                path_ref.display(),
                e
            ))
        })?;

        Self::load_from_str(&content, schema)
    }

    /// Loads policies from all `.cedar` files in a directory in deterministic order.
    pub fn load_from_dir<P: AsRef<Path>>(
        dir: P,
        schema: &Schema,
    ) -> Result<(PolicySet, Digest), PolicyError> {
        let dir_ref = dir.as_ref();
        if !dir_ref.is_dir() {
            return Err(PolicyError::InitializationFailed(format!(
                "'{}' is not a directory",
                dir_ref.display()
            )));
        }

        let mut entries = Vec::new();
        let read_dir = std::fs::read_dir(dir_ref).map_err(|e| {
            PolicyError::InitializationFailed(format!(
                "Failed to read directory '{}': {}",
                dir_ref.display(),
                e
            ))
        })?;

        for entry in read_dir {
            let entry = entry.map_err(|e| {
                PolicyError::InitializationFailed(format!("Failed to read dir entry: {e}"))
            })?;
            let p = entry.path();
            if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("cedar") {
                entries.push(p);
            }
        }

        if entries.is_empty() {
            return Err(PolicyError::InitializationFailed(format!(
                "No .cedar policy files found in '{}'",
                dir_ref.display()
            )));
        }

        // Sort deterministically by filename
        entries.sort();

        let mut combined_src = String::new();
        for file_path in entries {
            let file_content = std::fs::read_to_string(&file_path).map_err(|e| {
                PolicyError::InitializationFailed(format!(
                    "Failed to read policy file '{}': {}",
                    file_path.display(),
                    e
                ))
            })?;
            combined_src.push_str(&format!("// Source: {}\n", file_path.display()));
            combined_src.push_str(&file_content);
            combined_src.push('\n');
        }

        Self::load_from_str(&combined_src, schema)
    }

    /// Loads the default bundled Relay policy set.
    pub fn default_policy_set(schema: &Schema) -> Result<(PolicySet, Digest), PolicyError> {
        Self::load_from_str(RELAY_DEFAULT_POLICIES, schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::default_schema;

    #[test]
    fn test_default_policies_load_and_validate() {
        let schema = default_schema().expect("schema");
        let (policies, digest) =
            PolicyLoader::default_policy_set(&schema).expect("default policies must validate");

        assert!(!policies.is_empty());
        assert!(!digest.to_hex().is_empty());
    }

    #[test]
    fn test_policy_digest_determinism() {
        let text1 = "permit(principal, action, resource);";
        let text2 = "permit(principal, action, resource);";
        let text3 = "forbid(principal, action, resource);";

        assert_eq!(
            PolicyLoader::compute_policy_digest(text1),
            PolicyLoader::compute_policy_digest(text2)
        );
        assert_ne!(
            PolicyLoader::compute_policy_digest(text1),
            PolicyLoader::compute_policy_digest(text3)
        );
    }
}
