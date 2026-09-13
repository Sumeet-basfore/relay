//! Cedar Schema management and validation for Relay.
//!
//! Provides the strongly typed schema defining valid Relay entities (Agent, File, Table, Repository),
//! actions (fs.*, postgres.*, github.*), and execution context attributes.

use cedar_policy::Schema;
use relay_domain::PolicyError;
use std::path::Path;

/// Authoritative default Cedar schema definition for Relay.
pub const RELAY_DEFAULT_SCHEMA: &str = include_str!("../../../policies/relay_schema.cedarschema");

/// Parses and validates a Cedar schema from string.
pub fn parse_schema(schema_src: &str) -> Result<Schema, PolicyError> {
    let (schema, warnings) = Schema::from_cedarschema_str(schema_src)
        .map_err(|e| PolicyError::SchemaError(e.to_string()))?;

    for warning in warnings {
        tracing::warn!(warning = %warning, "Cedar schema warning");
    }

    Ok(schema)
}

/// Loads and validates a Cedar schema from a file.
pub fn load_schema_from_file<P: AsRef<Path>>(path: P) -> Result<Schema, PolicyError> {
    let path_ref = path.as_ref();
    let content = std::fs::read_to_string(path_ref).map_err(|e| {
        PolicyError::InitializationFailed(format!(
            "Failed to read schema file at '{}': {}",
            path_ref.display(),
            e
        ))
    })?;

    parse_schema(&content)
}

/// Returns the compiled default Relay Cedar schema.
pub fn default_schema() -> Result<Schema, PolicyError> {
    parse_schema(RELAY_DEFAULT_SCHEMA)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_schema_validity() {
        let schema = default_schema().expect("Default schema must compile cleanly");
        let _ = schema;
    }
}
