//! Tool schema pinning and deterministic SchemaDigest calculation.
//!
//! A tool's security boundary is bound to its input schema. Changing the schema
//! alters the computed `SchemaDigest`, invalidating cached policies or approvals.

use relay_domain::{CanonicalizationError, SchemaDigest, ToolSchema};
use serde_json::Value;

use crate::jcs::canonicalize_value;

/// Computes the deterministic cryptographic `SchemaDigest` of a JSON schema
/// using its RFC 8785 canonical bytes.
pub fn compute_schema_digest(schema: &Value) -> Result<SchemaDigest, CanonicalizationError> {
    let canonical_bytes = canonicalize_value(schema)?;
    Ok(SchemaDigest::compute(&canonical_bytes))
}

/// Creates a `ToolSchema` with its schema digest pinned to the RFC 8785 canonical bytes.
pub fn pin_tool_schema(schema: Value) -> Result<ToolSchema, CanonicalizationError> {
    let digest = compute_schema_digest(&schema)?;
    Ok(ToolSchema::with_digest(schema, digest))
}
