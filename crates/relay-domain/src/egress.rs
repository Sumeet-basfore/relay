use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::DomainError;
use crate::id::ActionHash;
use crate::principal::Principal;

/// Strongly typed identifier for an ephemeral proxy session
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxySessionId(String);

impl ProxySessionId {
    pub fn new() -> Self {
        Self(format!("proxy-{}", Uuid::now_v7()))
    }

    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ProxySessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProxySessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Normalized network endpoint target for egress mediation and Cedar PDP evaluation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_prefix: Option<String>,
}

impl NetworkEndpoint {
    pub fn new(scheme: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            scheme: scheme.into().to_ascii_lowercase(),
            host: host.into().to_ascii_lowercase(),
            port,
            path_prefix: None,
        }
    }

    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = Some(prefix.into());
        self
    }

    /// Parse a target URL / host string into a canonical NetworkEndpoint
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let trimmed = input.trim();
        let (scheme, host_port, path) = if let Some(idx) = trimmed.find("://") {
            let scheme = &trimmed[..idx];
            let rest = &trimmed[idx + 3..];
            let (hp, p) = match rest.find('/') {
                Some(p_idx) => (&rest[..p_idx], Some(&rest[p_idx..])),
                None => (rest, None),
            };
            (scheme.to_ascii_lowercase(), hp, p)
        } else {
            let (hp, p) = match trimmed.find('/') {
                Some(p_idx) => (&trimmed[..p_idx], Some(&trimmed[p_idx..])),
                None => (trimmed, None),
            };
            ("https".to_string(), hp, p)
        };

        let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
            let host_part = &host_port[..colon_idx];
            let port_part = &host_port[colon_idx + 1..];
            let parsed_port = port_part.parse::<u16>().map_err(|e| {
                DomainError::InvalidResource(format!(
                    "Invalid port '{}' in endpoint: {}",
                    port_part, e
                ))
            })?;
            (host_part.to_ascii_lowercase(), parsed_port)
        } else {
            let default_port = if scheme == "http" { 80 } else { 443 };
            (host_port.to_ascii_lowercase(), default_port)
        };

        if host.is_empty() {
            return Err(DomainError::InvalidResource(
                "Endpoint host cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            scheme,
            host,
            port,
            path_prefix: path.map(|p| p.to_string()),
        })
    }

    pub fn to_uri(&self) -> String {
        let default_port = if self.scheme == "http" { 80 } else { 443 };
        let host_port = if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };

        if let Some(prefix) = &self.path_prefix {
            format!("{}://{}{}", self.scheme, host_port, prefix)
        } else {
            format!("{}://{}", self.scheme, host_port)
        }
    }
}

impl fmt::Display for NetworkEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl FromStr for NetworkEndpoint {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Lifecycle state for an ephemeral proxy session lease
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxySessionState {
    Active,
    Consumed,
    Expired,
    Revoked,
}

impl fmt::Display for ProxySessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Consumed => write!(f, "Consumed"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

/// Ephemeral proxy lease granted to a subprocess for outbound network mediation (SI-020)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyLease {
    pub session_id: ProxySessionId,
    pub token: String,
    pub action_hash: ActionHash,
    pub principal: Principal,
    pub endpoint: Option<NetworkEndpoint>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: ProxySessionState,
}

impl ProxyLease {
    pub fn new(
        session_id: ProxySessionId,
        token: String,
        action_hash: ActionHash,
        principal: Principal,
        endpoint: Option<NetworkEndpoint>,
        ttl_seconds: u64,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_seconds as i64);
        Self {
            session_id,
            token,
            action_hash,
            principal,
            endpoint,
            created_at: now,
            expires_at,
            state: ProxySessionState::Active,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.state == ProxySessionState::Active && Utc::now() <= self.expires_at
    }

    pub fn mark_consumed(&mut self) {
        self.state = ProxySessionState::Consumed;
    }

    pub fn mark_revoked(&mut self) {
        self.state = ProxySessionState::Revoked;
    }

    pub fn check_expiration(&mut self) {
        if self.state == ProxySessionState::Active && Utc::now() > self.expires_at {
            self.state = ProxySessionState::Expired;
        }
    }
}

/// Captured outbound HTTP request through Relay loopback proxy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body_hash: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Cedar policy evaluation decision on outbound egress
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressDecision {
    Allow,
    Deny { reason: String },
    RequireStepUp { reason: String },
}

/// Outcome of mediated egress dispatch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressOutcome {
    Success {
        status_code: u16,
        bytes_transferred: usize,
    },
    Failed {
        error: String,
    },
    Blocked {
        reason: String,
    },
    TimedOut,
}
