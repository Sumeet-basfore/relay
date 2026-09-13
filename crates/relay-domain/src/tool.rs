use crate::id::{SchemaDigest, ToolId};
use serde::{Deserialize, Serialize};

/// Route classification for tool execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRoute {
    /// In-process native connector (GitHub, Postgres, Filesystem)
    NativeConnector,
    /// Out-of-process MCP subprocess with egress proxy interception
    SubprocessProxy,
}

/// Trust classification of the tool implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTrustClassification {
    /// Trusted in-binary code (part of Relay TCB)
    TcbNative,
    /// Partially trusted child subprocess (zero ambient credentials, scrubbed env)
    GovernedSubprocess,
}

/// A registered, namespaced MCP capability with pinned schema digest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    pub id: ToolId,
    pub description: Option<String>,
    pub schema: ToolSchema,
    pub route: ToolRoute,
    pub trust_classification: ToolTrustClassification,
}

impl Tool {
    pub fn new_native(
        id: ToolId,
        description: Option<String>,
        input_schema: serde_json::Value,
    ) -> Self {
        let schema = ToolSchema::new(input_schema);
        Self {
            id,
            description,
            schema,
            route: ToolRoute::NativeConnector,
            trust_classification: ToolTrustClassification::TcbNative,
        }
    }

    pub fn new_subprocess(
        id: ToolId,
        description: Option<String>,
        input_schema: serde_json::Value,
    ) -> Self {
        let schema = ToolSchema::new(input_schema);
        Self {
            id,
            description,
            schema,
            route: ToolRoute::SubprocessProxy,
            trust_classification: ToolTrustClassification::GovernedSubprocess,
        }
    }
}

/// The tool schema and its cryptographic SHA-256 digest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    pub input_schema: serde_json::Value,
    pub schema_digest: SchemaDigest,
}

impl ToolSchema {
    pub fn new(input_schema: serde_json::Value) -> Self {
        let raw_bytes = serde_json::to_vec(&input_schema).unwrap_or_default();
        let schema_digest = SchemaDigest::compute(&raw_bytes);
        Self {
            input_schema,
            schema_digest,
        }
    }

    pub fn with_digest(input_schema: serde_json::Value, schema_digest: SchemaDigest) -> Self {
        Self {
            input_schema,
            schema_digest,
        }
    }
}

/// Canonical tool identity binding server, namespace, name, and optional version
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ToolIdentity {
    pub server_id: String,
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}

impl ToolIdentity {
    pub fn new(
        server_id: impl Into<String>,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            namespace: namespace.into(),
            name: name.into(),
            version: None,
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Canonical string identifier in the format `server:namespace.name`
    pub fn canonical_id(&self) -> String {
        format!("{}:{}.{}", self.server_id, self.namespace, self.name)
    }

    /// Parse a tool string formatted as `server:namespace.name`, `server.namespace.name`,
    /// `namespace.name`, or `name`.
    pub fn parse(s: &str) -> Result<Self, crate::error::DomainError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(crate::error::DomainError::InvalidIdentifier(
                "Tool identity cannot be empty".into(),
            ));
        }

        // Format 1: server::namespace::name
        if let Some((server, rest)) = trimmed.split_once("::") {
            if let Some((ns, name)) = rest.split_once("::") {
                return Ok(Self::new(server, ns, name));
            }
            if let Some((ns, name)) = rest.split_once('.') {
                return Ok(Self::new(server, ns, name));
            }
            return Ok(Self::new(server, "default", rest));
        }

        // Format 2: server:namespace.name
        if let Some((server, rest)) = trimmed.split_once(':') {
            if let Some((ns, name)) = rest.split_once('.') {
                return Ok(Self::new(server, ns, name));
            }
            return Ok(Self::new(server, "default", rest));
        }

        // Format 3: server.namespace.name or namespace.name or name
        let parts: Vec<&str> = trimmed.split('.').collect();
        match parts.len() {
            1 => Ok(Self::new("default", "default", parts[0])),
            2 => Ok(Self::new("default", parts[0], parts[1])),
            3 => Ok(Self::new(parts[0], parts[1], parts[2])),
            _ => Err(crate::error::DomainError::InvalidIdentifier(format!(
                "Invalid tool identity format '{s}'; expected '[server:][namespace.]name'"
            ))),
        }
    }

    /// Convert to ToolId
    pub fn to_tool_id(&self) -> Result<ToolId, crate::error::DomainError> {
        ToolId::new(&self.namespace, &self.name)
    }
}

impl std::fmt::Display for ToolIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical_id())
    }
}
