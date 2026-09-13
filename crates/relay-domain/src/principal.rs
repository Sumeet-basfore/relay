use crate::id::{AgentId, PrincipalId};
use serde::{Deserialize, Serialize};

/// Authenticated identity capable of proposing an action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    User(UserPrincipal),
    Agent(AgentPrincipal),
}

impl Principal {
    pub fn id(&self) -> &PrincipalId {
        match self {
            Self::User(u) => &u.id,
            Self::Agent(a) => &a.id,
        }
    }

    pub fn is_agent(&self) -> bool {
        matches!(self, Self::Agent(_))
    }

    pub fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
    }
}

/// Human user principal operating the local machine
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPrincipal {
    pub id: PrincipalId,
    pub username: String,
    pub realm: String,
}

impl UserPrincipal {
    pub fn new_local(username: impl Into<String>) -> Result<Self, crate::error::DomainError> {
        let name = username.into();
        let id_str = format!("principal:user:local:{name}");
        Ok(Self {
            id: PrincipalId::new(id_str)?,
            username: name,
            realm: "local".to_string(),
        })
    }
}

/// Autonomous agent principal (e.g. Claude Code, Cursor, custom loop)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub id: PrincipalId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub version: String,
    pub parent: Option<PrincipalId>,
    pub lineage: Vec<PrincipalId>,
}

impl AgentPrincipal {
    pub fn new(
        agent_name: impl Into<String>,
        version: impl Into<String>,
        parent: Option<PrincipalId>,
    ) -> Result<Self, crate::error::DomainError> {
        let name = agent_name.into();
        let ver = version.into();
        let id_str = format!("principal:agent:{name}:{ver}");
        let id = PrincipalId::new(id_str)?;
        let agent_id = AgentId::new(format!("{name}:{ver}"))?;
        let lineage = if let Some(ref p) = parent {
            vec![p.clone()]
        } else {
            Vec::new()
        };

        Ok(Self {
            id,
            agent_id,
            agent_name: name,
            version: ver,
            parent,
            lineage,
        })
    }
}

/// High-level Agent entity description
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    pub id: AgentId,
    pub name: String,
    pub description: Option<String>,
    pub client_type: String,
}
