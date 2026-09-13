//! Canonical tool identity validation and parsing.
//!
//! Enforces collision-resistant tool identities across servers, namespaces, and names.

use relay_domain::CanonicalizationError;
pub use relay_domain::ToolIdentity;

/// Validates that a `ToolIdentity` conforms to Relay security requirements.
///
/// Ensures server ID, namespace, and tool name are non-empty and contain only safe characters.
pub fn validate_tool_identity(id: &ToolIdentity) -> Result<(), CanonicalizationError> {
    let canonical = id.canonical_id();
    if id.server_id.trim().is_empty() {
        return Err(CanonicalizationError::InvalidToolIdentity(
            canonical,
            "server_id cannot be empty".to_string(),
        ));
    }
    if id.namespace.trim().is_empty() {
        return Err(CanonicalizationError::InvalidToolIdentity(
            canonical,
            "namespace cannot be empty".to_string(),
        ));
    }
    if id.name.trim().is_empty() {
        return Err(CanonicalizationError::InvalidToolIdentity(
            canonical,
            "tool name cannot be empty".to_string(),
        ));
    }

    let is_safe = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';

    if !id.server_id.chars().all(is_safe) {
        return Err(CanonicalizationError::InvalidToolIdentity(
            canonical,
            format!(
                "invalid characters in server_id '{}'; expected alphanumeric, '-', or '_'",
                id.server_id
            ),
        ));
    }
    if !id.namespace.chars().all(is_safe) {
        return Err(CanonicalizationError::InvalidToolIdentity(
            canonical,
            format!(
                "invalid characters in namespace '{}'; expected alphanumeric, '-', or '_'",
                id.namespace
            ),
        ));
    }
    if !id.name.chars().all(is_safe) {
        return Err(CanonicalizationError::InvalidToolIdentity(
            canonical,
            format!(
                "invalid characters in tool name '{}'; expected alphanumeric, '-', or '_'",
                id.name
            ),
        ));
    }

    Ok(())
}
