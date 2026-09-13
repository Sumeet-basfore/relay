use crate::error::DomainError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Universal canonical resource URI (e.g. "file:///workspace/repo/main.rs", "github://github.com/org/repo")
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceUri(String);

impl ResourceUri {
    pub fn parse(uri_str: &str) -> Result<Self, DomainError> {
        let trimmed = uri_str.trim();
        if trimmed.is_empty() {
            return Err(DomainError::InvalidResource(
                "Resource URI cannot be empty".into(),
            ));
        }
        if !trimmed.contains("://") {
            return Err(DomainError::InvalidResource(format!(
                "Resource URI must contain scheme (e.g. 'file://', 'github://', 'postgres://'), got '{trimmed}'"
            )));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn scheme(&self) -> &str {
        self.0.split("://").next().unwrap_or("")
    }

    pub fn path(&self) -> &str {
        self.0.split("://").nth(1).unwrap_or("")
    }
}

impl fmt::Debug for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResourceUri({})", self.0)
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Resource value object with domain metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub uri: ResourceUri,
    pub namespace: String,
    pub environment: String,
}

impl Resource {
    pub fn new(
        uri: ResourceUri,
        namespace: impl Into<String>,
        environment: impl Into<String>,
    ) -> Self {
        Self {
            uri,
            namespace: namespace.into(),
            environment: environment.into(),
        }
    }
}
