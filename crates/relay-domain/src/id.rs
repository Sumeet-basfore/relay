use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::DomainError;

/// Generic SHA-256 Digest wrapper representing a 32-byte hash
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write;
            let _ = write!(hex, "{:02x}", byte);
        }
        hex
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, DomainError> {
        let cleaned = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let cleaned = cleaned.strip_prefix("sha256:").unwrap_or(cleaned);
        if cleaned.len() != 64 {
            return Err(DomainError::InvalidIdentifier(format!(
                "Invalid SHA-256 hex length: expected 64 chars, got {}",
                cleaned.len()
            )));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).map_err(|e| {
                DomainError::InvalidIdentifier(format!("Invalid hex character in digest: {e}"))
            })?;
        }
        Ok(Self(bytes))
    }

    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

macro_rules! define_digest_type {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Digest);

        impl $name {
            pub fn compute(data: &[u8]) -> Self {
                Self(Digest::compute(data))
            }

            pub fn from_hex(hex_str: &str) -> Result<Self, DomainError> {
                Digest::from_hex(hex_str).map(Self)
            }

            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_digest_type!(
    ActionHash,
    "Cryptographic SHA-256 hash of the canonical AuthorizationRequest"
);
define_digest_type!(
    OutputHash,
    "Cryptographic SHA-256 hash of the execution output"
);
define_digest_type!(
    SchemaDigest,
    "Cryptographic SHA-256 hash of the tool JSON schema"
);
define_digest_type!(
    PolicySetDigest,
    "Cryptographic SHA-256 hash of the active Cedar policy set"
);

macro_rules! define_uuid_id {
    ($name:ident, $prefix:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub fn to_prefixed_string(&self) -> String {
                format!("{}_{}", $prefix, self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new_v7()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let stripped = if let Some(rest) = s.strip_prefix(concat!($prefix, "_")) {
                    rest
                } else if let Some(rest) = s.strip_prefix($prefix) {
                    rest
                } else {
                    s
                };

                Uuid::parse_str(stripped).map(Self).map_err(|e| {
                    DomainError::InvalidIdentifier(format!(
                        "Invalid {} string '{}': {}",
                        stringify!($name),
                        s,
                        e
                    ))
                })
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_uuid_id!(
    SessionId,
    "sess",
    "Typed unique identifier for an active agent session"
);
define_uuid_id!(
    ActionId,
    "act",
    "Typed unique identifier for a proposed/governed action"
);
define_uuid_id!(
    DecisionId,
    "dec",
    "Typed unique identifier for a Cedar policy decision"
);
define_uuid_id!(
    ApprovalId,
    "appr",
    "Typed unique identifier for an interactive human approval"
);
define_uuid_id!(
    LeaseId,
    "lease",
    "Typed unique identifier for an ephemeral credential lease"
);
define_uuid_id!(
    ExecutionId,
    "exec",
    "Typed unique identifier for an action execution attempt"
);
define_uuid_id!(
    ReceiptId,
    "rcpt",
    "Typed unique identifier for an ActionReceipt"
);

/// Monotonically increasing sequence number in the SQLite ledger
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SequenceNumber(pub u64);

impl SequenceNumber {
    pub const GENESIS: Self = Self(0);

    pub fn next(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly typed Principal Identifier in URN format (e.g. "principal:user:local:sumeet")
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let s = id.into();
        if s.trim().is_empty() {
            return Err(DomainError::InvalidIdentifier(
                "PrincipalId cannot be empty".into(),
            ));
        }
        if !s.starts_with("principal:") {
            return Err(DomainError::InvalidIdentifier(format!(
                "PrincipalId must start with 'principal:', got '{s}'"
            )));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrincipalId({})", self.0)
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly typed Agent Identifier in URN format (e.g. "agent:claude-code:v1.0")
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let s = id.into();
        if s.trim().is_empty() {
            return Err(DomainError::InvalidIdentifier(
                "AgentId cannot be empty".into(),
            ));
        }
        if !s.starts_with("agent:") {
            return Err(DomainError::InvalidIdentifier(format!(
                "AgentId must start with 'agent:', got '{s}'"
            )));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({})", self.0)
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly typed Tool Identifier in namespaced format (e.g. "github.create_issue")
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolId(String);

impl ToolId {
    pub fn new(namespace: &str, tool_name: &str) -> Result<Self, DomainError> {
        if namespace.trim().is_empty() || tool_name.trim().is_empty() {
            return Err(DomainError::InvalidIdentifier(
                "Tool namespace and name cannot be empty".into(),
            ));
        }
        if namespace.contains('.') || tool_name.contains('.') {
            return Err(DomainError::InvalidIdentifier(
                "Tool namespace and name cannot contain dots".into(),
            ));
        }
        Ok(Self(format!("{namespace}.{tool_name}")))
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            return Err(DomainError::InvalidIdentifier(format!(
                "ToolId must be formatted as '<namespace>.<tool_name>', got '{s}'"
            )));
        }
        Ok(Self(s.to_string()))
    }

    pub fn namespace(&self) -> &str {
        self.0.split('.').next().unwrap_or("")
    }

    pub fn tool_name(&self) -> &str {
        self.0.split('.').nth(1).unwrap_or("")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ToolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ToolId({})", self.0)
    }
}

impl fmt::Display for ToolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
