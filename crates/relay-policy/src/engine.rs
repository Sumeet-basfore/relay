//! Cedar Policy Decision Point (PDP) Engine implementation.
//!
//! Enforces deterministic authorization, strict default-deny, cryptographic policy digest binding (SI-010),
//! and step-up approval annotations.

use async_trait::async_trait;
use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Request, Schema};
use relay_domain::{AuthorizationRequest, Digest, PolicyDecision, PolicyEngine, PolicyError};
use std::path::Path;

use crate::loader::PolicyLoader;
use crate::mapping::map_authorization_request;
use crate::schema::{default_schema, load_schema_from_file, parse_schema};

/// Cedar Policy Engine implementing the domain `PolicyEngine` contract.
#[derive(Clone)]
pub struct CedarPolicyEngine {
    schema: Schema,
    policy_set: PolicySet,
    policy_digest: Digest,
    authorizer: Authorizer,
    entities: Entities,
}

impl CedarPolicyEngine {
    /// Creates a new CedarPolicyEngine with pre-compiled schema, policies, and digest.
    pub fn new(schema: Schema, policy_set: PolicySet, policy_digest: Digest) -> Self {
        Self {
            schema,
            policy_set,
            policy_digest,
            authorizer: Authorizer::new(),
            entities: Entities::empty(),
        }
    }

    /// Initializes a CedarPolicyEngine from raw policy and schema strings.
    pub fn from_str(policy_src: &str, schema_src: Option<&str>) -> Result<Self, PolicyError> {
        let schema = match schema_src {
            Some(src) => parse_schema(src)?,
            None => default_schema()?,
        };

        let (policy_set, policy_digest) = PolicyLoader::load_from_str(policy_src, &schema)?;
        Ok(Self::new(schema, policy_set, policy_digest))
    }

    /// Initializes a CedarPolicyEngine from policy and schema file paths.
    pub fn from_file<P: AsRef<Path>>(
        policy_path: P,
        schema_path: Option<P>,
    ) -> Result<Self, PolicyError> {
        let schema = match schema_path {
            Some(p) => load_schema_from_file(p)?,
            None => default_schema()?,
        };

        let (policy_set, policy_digest) = PolicyLoader::load_from_file(policy_path, &schema)?;
        Ok(Self::new(schema, policy_set, policy_digest))
    }

    /// Initializes a CedarPolicyEngine from a directory of `.cedar` policies.
    pub fn from_dir<P: AsRef<Path>>(
        policy_dir: P,
        schema_path: Option<P>,
    ) -> Result<Self, PolicyError> {
        let schema = match schema_path {
            Some(p) => load_schema_from_file(p)?,
            None => default_schema()?,
        };

        let (policy_set, policy_digest) = PolicyLoader::load_from_dir(policy_dir, &schema)?;
        Ok(Self::new(schema, policy_set, policy_digest))
    }

    /// Initializes the engine using default schema and bundled policies.
    pub fn default_engine() -> Result<Self, PolicyError> {
        let schema = default_schema()?;
        let (policy_set, policy_digest) = PolicyLoader::default_policy_set(&schema)?;
        Ok(Self::new(schema, policy_set, policy_digest))
    }

    /// Returns the active `Schema`.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Returns the active `PolicySet`.
    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }

    /// Returns the active `PolicySetDigest`.
    pub fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    fn evaluate_internal(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<PolicyDecision, PolicyError> {
        let action_hash = request.compute_action_hash();

        // Map request to Cedar PARC tuple
        let (principal, action, resource, context) = map_authorization_request(request)?;

        let cedar_request =
            Request::new(principal, action, resource, context, None).map_err(|e| {
                PolicyError::EvaluationFailed(format!("Invalid authorization request: {e}"))
            })?;

        let response =
            self.authorizer
                .is_authorized(&cedar_request, &self.policy_set, &self.entities);

        let diagnostics_errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        let determining_policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| {
                if let Some(p) = self.policy_set.policy(id) {
                    if let Some(annotated_id) = p.annotation("id") {
                        return annotated_id.to_string();
                    }
                }
                id.to_string()
            })
            .collect();

        match response.decision() {
            Decision::Allow => {
                // Check if any determining policy specifies step-up human approval
                let mut requires_approval = false;
                let mut approval_reason = None;

                for pid in response.diagnostics().reason() {
                    if let Some(policy) = self.policy_set.policy(pid) {
                        if let Some(msg) = policy.annotation("approval_required") {
                            requires_approval = true;
                            approval_reason = Some(msg.to_string());
                            break;
                        }
                        if let Some(msg) = policy.annotation("approval") {
                            requires_approval = true;
                            approval_reason = Some(msg.to_string());
                            break;
                        }
                        if let Some(advice) = policy.annotation("advice") {
                            if advice.contains("REQUIRE_HUMAN_APPROVAL") {
                                requires_approval = true;
                                approval_reason = Some(advice.to_string());
                                break;
                            }
                        }
                    }
                }

                if requires_approval {
                    let mut decision = PolicyDecision::approval_required(
                        action_hash,
                        self.policy_digest,
                        approval_reason.unwrap_or_else(|| {
                            "Step-up interactive human approval required".to_string()
                        }),
                        determining_policies,
                    );
                    decision.diagnostics = diagnostics_errors;
                    Ok(decision)
                } else {
                    let mut decision = PolicyDecision::allow(
                        action_hash,
                        self.policy_digest,
                        determining_policies,
                    );
                    decision.diagnostics = diagnostics_errors;
                    Ok(decision)
                }
            }
            Decision::Deny => {
                let reason = if !determining_policies.is_empty() {
                    "Action explicitly forbidden by policy".to_string()
                } else {
                    "Action not permitted by policy (default deny)".to_string()
                };

                let mut decision = PolicyDecision::deny(
                    action_hash,
                    self.policy_digest,
                    reason,
                    determining_policies,
                );
                decision.diagnostics = diagnostics_errors;
                Ok(decision)
            }
        }
    }
}

#[async_trait]
impl PolicyEngine for CedarPolicyEngine {
    async fn evaluate(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<PolicyDecision, PolicyError> {
        // Enforce SI-014: Fail-closed on panic during evaluation
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.evaluate_internal(request)
        }));

        match result {
            Ok(eval_result) => eval_result,
            Err(panic_err) => {
                let panic_msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic during Cedar evaluation".to_string()
                };

                tracing::error!(panic = %panic_msg, "Cedar PDP panicked; failing closed (SI-014)");
                Err(PolicyError::EvaluationFailed(format!(
                    "Panic during policy evaluation: {panic_msg}"
                )))
            }
        }
    }

    fn policy_digest(&self) -> Digest {
        self.policy_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use relay_domain::{PolicyDecisionType, PrincipalId, ResourceUri, SessionId, ToolId};
    use serde_json::json;

    #[tokio::test]
    async fn test_default_engine_allows_fs_read() {
        let engine = CedarPolicyEngine::default_engine().expect("default engine");

        let request = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "fs.read".to_string(),
            resource: ResourceUri::parse("file:///workspace/project/README.md").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("fs", "read").unwrap(),
            arguments: json!({ "path": "/workspace/project/README.md" }),
            working_directory: "/workspace/project".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let decision = engine.evaluate(&request).await.expect("evaluate");
        assert_eq!(decision.decision, PolicyDecisionType::Allow);
        assert_eq!(decision.policy_digest, engine.policy_digest());
    }

    #[tokio::test]
    async fn test_default_engine_forbids_env_file() {
        let engine = CedarPolicyEngine::default_engine().expect("default engine");

        let request = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "fs.read".to_string(),
            resource: ResourceUri::parse("file:///workspace/project/.env").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("fs", "read").unwrap(),
            arguments: json!({ "path": "/workspace/project/.env" }),
            working_directory: "/workspace/project".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let decision = engine.evaluate(&request).await.expect("evaluate");
        assert_eq!(decision.decision, PolicyDecisionType::Deny);
        assert!(!decision.determining_policies.is_empty());
    }

    #[tokio::test]
    async fn test_default_engine_requires_approval_on_delete() {
        let engine = CedarPolicyEngine::default_engine().expect("default engine");

        let request = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "fs.delete".to_string(),
            resource: ResourceUri::parse("file:///workspace/project/scratch.txt").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("fs", "delete").unwrap(),
            arguments: json!({ "path": "/workspace/project/scratch.txt" }),
            working_directory: "/workspace/project".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let decision = engine.evaluate(&request).await.expect("evaluate");
        assert_eq!(decision.decision, PolicyDecisionType::ApprovalRequired);
        assert!(decision.requires_approval());
    }

    #[tokio::test]
    async fn test_default_engine_unmatched_action_default_deny() {
        let engine = CedarPolicyEngine::default_engine().expect("default engine");

        let request = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "unknown.tool".to_string(),
            resource: ResourceUri::parse("file:///workspace/foo").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("unknown", "tool").unwrap(),
            arguments: json!({}),
            working_directory: "/workspace".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let decision = engine.evaluate(&request).await.expect("evaluate");
        assert_eq!(decision.decision, PolicyDecisionType::Deny);
        assert!(decision.determining_policies.is_empty());
    }
}
