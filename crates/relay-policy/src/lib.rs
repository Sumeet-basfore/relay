//! AWS Cedar Policy Decision Point (PDP) integration for Relay.
//!
//! Evaluates deterministic, formally verified Cedar authorization policies over canonical actions.
//! Enforces:
//! - Strict Default Deny (unauthorized actions never executed)
//! - Cryptographic Policy Set Digest Binding (SI-010)
//! - Step-Up Human Operator Approval via Cedar Annotations (`@advice`, `@approval_required`)
//! - Strict Compile-Time and Runtime Schema Validation
//! - Fail-Closed Execution Boundaries (SI-014)

pub mod engine;
pub mod loader;
pub mod mapping;
pub mod schema;

pub use cedar_policy;
pub use engine::CedarPolicyEngine;
pub use loader::{PolicyLoader, RELAY_DEFAULT_POLICIES};
pub use mapping::map_authorization_request;
pub use schema::{default_schema, load_schema_from_file, parse_schema, RELAY_DEFAULT_SCHEMA};
