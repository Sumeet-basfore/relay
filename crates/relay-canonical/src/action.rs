//! CanonicalAction domain model and ActionCanonicalizer pipeline.
//!
//! Provides the single source of truth for Relay action authorization and execution:
//! MCP tool call -> ToolCallContext -> ActionCanonicalizer -> CanonicalAction -> ActionHash.

use chrono::{DateTime, Utc};
use relay_domain::{
    ActionHash, ActionId, AuthorizationRequest, CanonicalizationError, DomainError,
    ExecutionEnvironment, PrincipalId, ResourceResolver, ResourceUri, SchemaDigest, SessionId,
    ToolIdentity, ToolSchema,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

use crate::jcs::canonicalize_value;
use crate::resource::fs::FilesystemNormalizer;
use crate::resource::github::GitHubNormalizer;
use crate::resource::resolver::DefaultResourceResolver;
use crate::resource::sql::SqlNormalizer;
use crate::schema::compute_schema_digest;
use crate::tool_identity::validate_tool_identity;

/// Payload serialized via RFC 8785 (JCS) to produce authoritative ActionHash
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CanonicalActionPayload<'a> {
    pub session_id: &'a SessionId,
    pub principal: &'a PrincipalId,
    pub mcp_method: &'a str,
    pub tool: String,
    pub resource: String,
    pub arguments: &'a Value,
    pub schema_digest: String,
    pub environment: &'a ExecutionEnvironment,
}

/// The authoritative canonical representation of an agent action.
///
/// Consumed by both Cedar policy authorization (B004) and execution dispatch (B006),
/// guaranteeing zero authorization/execution divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAction {
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub principal: PrincipalId,
    pub mcp_method: String,
    pub tool: ToolIdentity,
    pub resource: ResourceUri,
    pub canonical_arguments: Value,
    pub schema_digest: SchemaDigest,
    pub environment: ExecutionEnvironment,
    pub action_hash: ActionHash,
    pub canonical_bytes: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl CanonicalAction {
    /// Builds an AuthorizationRequest for the Cedar PolicyEngine (B004 handoff)
    pub fn to_authorization_request(&self) -> Result<AuthorizationRequest, DomainError> {
        let tool_id = self.tool.to_tool_id()?;
        Ok(AuthorizationRequest {
            principal: self.principal.clone(),
            action: format!("{}:{}", self.tool.namespace, self.tool.name),
            resource: self.resource.clone(),
            session_id: self.session_id,
            tool: tool_id,
            arguments: self.canonical_arguments.clone(),
            working_directory: self.environment.cwd.clone(),
            timestamp: self.created_at,
            action_hash: Some(self.action_hash),
        })
    }
}

/// Pipeline processor transforming raw tool calls into canonical actions
#[derive(Clone)]
pub struct ActionCanonicalizer {
    resolver: Arc<dyn ResourceResolver>,
    fs_normalizer: FilesystemNormalizer,
    default_schema_digest: SchemaDigest,
}

impl Default for ActionCanonicalizer {
    fn default() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        Self::new(cwd)
    }
}

impl ActionCanonicalizer {
    pub fn new(base_dir: PathBuf) -> Self {
        let resolver = Arc::new(DefaultResourceResolver::new(base_dir.clone()));
        let fs_normalizer = FilesystemNormalizer::new(base_dir, false);
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        let default_schema_digest =
            compute_schema_digest(&empty_schema).unwrap_or_else(|_| SchemaDigest::compute(b"{}"));

        Self {
            resolver,
            fs_normalizer,
            default_schema_digest,
        }
    }

    pub fn with_resolver(resolver: Arc<dyn ResourceResolver>, base_dir: PathBuf) -> Self {
        let fs_normalizer = FilesystemNormalizer::new(base_dir, false);
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        let default_schema_digest =
            compute_schema_digest(&empty_schema).unwrap_or_else(|_| SchemaDigest::compute(b"{}"));

        Self {
            resolver,
            fs_normalizer,
            default_schema_digest,
        }
    }

    /// Canonicalizes a tool call into a `CanonicalAction`
    #[allow(clippy::too_many_arguments)]
    pub fn canonicalize(
        &self,
        session_id: SessionId,
        principal: PrincipalId,
        mcp_method: &str,
        tool: ToolIdentity,
        raw_arguments: &Value,
        schema: Option<&ToolSchema>,
        environment: Option<ExecutionEnvironment>,
    ) -> Result<CanonicalAction, CanonicalizationError> {
        validate_tool_identity(&tool)?;

        let mut canonical_arguments = raw_arguments.clone();

        // Perform domain-specific AST argument normalization
        if let Value::Object(ref mut map) = canonical_arguments {
            match tool.namespace.as_str() {
                "fs" | "file" | "filesystem" => {
                    if let Some(path_val) = map.get("path").and_then(|v| v.as_str()) {
                        let norm_path = self.fs_normalizer.resolve_path(path_val)?;
                        map.insert(
                            "path".to_string(),
                            Value::String(norm_path.canonical_path().to_string()),
                        );
                    }
                }
                "postgres" | "sql" | "db" => {
                    if let Some(query_val) = map.get("query").and_then(|v| v.as_str()) {
                        let norm_sql = SqlNormalizer::normalize(query_val)?;
                        map.insert("query".to_string(), Value::String(norm_sql.canonical_sql));
                    }
                }
                "github" | "gh" => {
                    if let Some(repo_val) = map.get("repo").and_then(|v| v.as_str()) {
                        let norm_gh = GitHubNormalizer::parse(repo_val)?;
                        map.insert(
                            "repo".to_string(),
                            Value::String(format!("{}/{}", norm_gh.owner, norm_gh.repo)),
                        );
                    }
                }
                _ => {}
            }
        }

        // Resolve target canonical resource URI
        let resource =
            self.resolver
                .resolve_resource(&tool.namespace, &tool.name, &canonical_arguments)?;

        // Pinned schema digest
        let schema_digest = match schema {
            Some(s) => s.schema_digest,
            None => self.default_schema_digest,
        };

        let environment = environment.unwrap_or_else(ExecutionEnvironment::current);

        // Serialize payload via RFC 8785 JCS to produce canonical bytes
        let payload = CanonicalActionPayload {
            session_id: &session_id,
            principal: &principal,
            mcp_method,
            tool: tool.canonical_id(),
            resource: resource.to_string(),
            arguments: &canonical_arguments,
            schema_digest: schema_digest.to_hex(),
            environment: &environment,
        };

        let payload_value = serde_json::to_value(&payload)
            .map_err(|e| CanonicalizationError::JcsError(e.to_string()))?;
        let canonical_bytes = canonicalize_value(&payload_value)?;
        let action_hash = ActionHash::compute(&canonical_bytes);

        Ok(CanonicalAction {
            action_id: ActionId::new_v7(),
            session_id,
            principal,
            mcp_method: mcp_method.to_string(),
            tool,
            resource,
            canonical_arguments,
            schema_digest,
            environment,
            action_hash,
            canonical_bytes,
            created_at: Utc::now(),
        })
    }
}
